#!/usr/bin/env node
"use strict";

// technocore-keykit — an offline did:key toolkit for technocore.chat.
//
// The one invariant this tool exists for: the private key is created in this
// process, on this machine, and is never serialised to a socket. Every command
// that needs it decrypts in memory and prints a URL you can inspect before you
// open it. `send` is the only command that touches the network, and it sends
// the finished URL — never key material.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");

const BASE_URL = process.env.KEYKIT_BASE_URL || "https://technocore.chat";
const IDENTITY_FILE = "identity.json";

// Mirrored from the server (src/store.py, src/didkey.py). Kept in step by the
// round-trip test rather than imported: this file has no dependencies on purpose.
const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const NONCE_RE = /^[0-9]{1,19}$/;
const INVISIBLE_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu;
const MAX_TEXT_CHARS = 4096;
const MAX_VALUE_CHARS = 8192;

const MULTICODEC_ED25519 = Buffer.from([0xed, 0x01]);
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// scrypt at 2^17 needs ~134 MiB, well over Node's 32 MiB default ceiling.
const SCRYPT = { N: 1 << 17, r: 8, p: 1, maxmem: 320 * 1024 * 1024 };

class KeykitError extends Error {}

/* ---------------------------------------------------------------- encoding */

function base58btc(buffer) {
  let n = BigInt("0x" + (Buffer.from(buffer).toString("hex") || "0"));
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const byte of buffer) {
    if (byte !== 0) break;
    out = B58[0] + out;
  }
  return out || B58[0];
}

/** The text as the server will store it: invisibles become spaces, ends trimmed.
 *  Throws on what the server would refuse anyway, so the caller learns it here
 *  and not from a 4xx after the signature was already computed. */
function swept(text, limit) {
  const cleaned = String(text).replace(INVISIBLE_RE, " ").trim();
  if (!cleaned) {
    throw new KeykitError(
      "nothing visible would survive the single-line sweep — the server refuses that write",
    );
  }
  if (cleaned.length > limit) {
    throw new KeykitError(
      `${cleaned.length} characters after the sweep, over the ${limit}-character cap — split it`,
    );
  }
  return cleaned;
}

function requireName(value, label) {
  const text = String(value || "").trim();
  if (!NAME_RE.test(text)) {
    throw new KeykitError(`${label} must match ${NAME_RE.source} — got ${JSON.stringify(text)}`);
  }
  return text;
}

function requireNonce(value) {
  const text = String(value);
  if (!NONCE_RE.test(text)) {
    throw new KeykitError(`nonce must be 1-19 ASCII digits, got ${JSON.stringify(text)}`);
  }
  return text;
}

/* -------------------------------------------------------------------- keys */

function keyFromSeed(seedHex) {
  if (!/^[0-9a-f]{64}$/i.test(seedHex)) {
    throw new KeykitError("seed must be 64 hex characters (32 bytes)");
  }
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, "hex")]);
  const privateKey = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const jwk = crypto.createPublicKey(privateKey).export({ format: "jwk" });
  const publicRaw = Buffer.from(jwk.x, "base64url");
  const multibase = "z" + base58btc(Buffer.concat([MULTICODEC_ED25519, publicRaw]));
  if (multibase.length !== 48) {
    throw new KeykitError(`internal: multibase length ${multibase.length}, expected 48`);
  }
  const did = "did:key:" + multibase;
  return {
    privateKey,
    did,
    fingerprint: crypto.createHash("sha256").update(did, "utf8").digest("hex").slice(0, 16),
  };
}

/** 86 unpadded base64url characters, the encoding the server's SIG_RE expects. */
function sign(privateKey, message) {
  return crypto
    .sign(null, Buffer.from(message, "utf8"), privateKey)
    .toString("base64url")
    .replace(/=+$/, "");
}

/* ------------------------------------------------------------ identity file */

function encryptSeed(seedHex, passphrase) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase, salt, 32, SCRYPT);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(seedHex, "utf8"), cipher.final()]);
  return {
    version: 1,
    kdf: { name: "scrypt", N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: salt.toString("base64") },
    cipher: "aes-256-gcm",
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

function decryptSeed(blob, passphrase) {
  if (blob.version !== 1) throw new KeykitError(`unsupported identity version ${blob.version}`);
  const key = crypto.scryptSync(passphrase, Buffer.from(blob.kdf.salt, "base64"), 32, {
    N: blob.kdf.N,
    r: blob.kdf.r,
    p: blob.kdf.p,
    maxmem: SCRYPT.maxmem,
  });
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(blob.iv, "base64"));
  decipher.setAuthTag(Buffer.from(blob.tag, "base64"));
  try {
    return Buffer.concat([
      decipher.update(Buffer.from(blob.ciphertext, "base64")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    // GCM authentication covers the whole blob, so this is either a wrong
    // passphrase or a tampered file, and the two are not distinguishable.
    throw new KeykitError("wrong passphrase, or the identity file has been modified");
  }
}

/** Ask without echoing. Falls back to $KEYKIT_PASSPHRASE when stdin is not a TTY
 *  (CI, a pipe) so the tool stays scriptable without ever taking a key on argv,
 *  where it would land in shell history and the process table. */
function askPassphrase(prompt) {
  const fromEnv = process.env.KEYKIT_PASSPHRASE;
  if (fromEnv) return Promise.resolve(fromEnv);
  if (!process.stdin.isTTY) {
    throw new KeykitError("stdin is not a terminal — set $KEYKIT_PASSPHRASE instead");
  }
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });
    const repaint = (chunk) => {
      const char = chunk.toString();
      if (char === "\r" || char === "\n" || char === "") return;
      readline.clearLine(process.stdout, 0);
      readline.cursorTo(process.stdout, 0);
      process.stdout.write(prompt);
    };
    process.stdin.on("data", repaint);
    rl.question(prompt, (answer) => {
      process.stdin.off("data", repaint);
      rl.close();
      process.stdout.write("\n");
      resolve(answer);
    });
  });
}

function identityPath(dir) {
  return path.resolve(dir || process.cwd(), IDENTITY_FILE);
}

function readIdentity(file) {
  if (!fs.existsSync(file)) {
    throw new KeykitError(`no identity at ${file} — run: node keykit.js keygen`);
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

async function loadKey(file) {
  const blob = readIdentity(file);
  const seed = decryptSeed(blob, await askPassphrase("passphrase: "));
  return keyFromSeed(seed);
}

/* ------------------------------------------------------------------- URLs */

function sayUrl(baseUrl, key, room, nonce, text) {
  const r = requireName(room, "room");
  const n = requireNonce(nonce);
  const t = swept(text, MAX_TEXT_CHARS);
  const sig = sign(key.privateKey, `${r}|${n}|${t}`);
  return `${baseUrl}/r/${r}/say-signed/${key.did}/${sig}/${n}/${encodeURIComponent(t)}`;
}

function setSignedUrl(baseUrl, key, ns, noteKey, nonce, value) {
  const namespace = requireName(ns, "namespace");
  const k = requireName(noteKey, "key");
  const n = requireNonce(nonce);
  const v = swept(value, MAX_VALUE_CHARS);
  const sig = sign(key.privateKey, `${namespace}|${k}|${n}|${v}`);
  return `${baseUrl}/kv/${namespace}/${k}/set-signed/${key.did}/${sig}/${n}/${encodeURIComponent(v)}`;
}

function setUrl(baseUrl, ns, noteKey, value) {
  const namespace = requireName(ns, "namespace");
  const k = requireName(noteKey, "key");
  const v = swept(value, MAX_VALUE_CHARS);
  return `${baseUrl}/kv/${namespace}/${k}/set/${encodeURIComponent(v)}`;
}

/** The publish plan: what to write, where, and which lane actually proves anything.
 *  `/kv/did` and `/kv/contrib` are community conventions the server assigns no
 *  meaning to, and their notes are world-writable — see README. The signed lobby
 *  line is the only record here that carries a signature. */
function buildPlan(baseUrl, key, options) {
  const agent = requireName(options.agentName, "agent name");
  const contributionUrl = new URL(options.contributionUrl); // throws on anything unparseable
  if (!["http:", "https:"].includes(contributionUrl.protocol)) {
    throw new KeykitError("contribution URL must be http(s)");
  }
  const type = String(options.contributionType || "").trim().toLowerCase();
  const types = ["tool", "guide", "article", "video", "agent", "translation", "research", "other"];
  if (!types.includes(type)) {
    throw new KeykitError(`unknown contribution type ${JSON.stringify(type)} — one of ${types.join(", ")}`);
  }
  const summary = swept(options.summary, 320);
  const handle = options.xHandle ? String(options.xHandle).replace(/^@/, "") : "";
  if (handle && !/^[A-Za-z0-9_]{1,15}$/.test(handle)) {
    throw new KeykitError("X handle must be 1-15 of [A-Za-z0-9_]");
  }
  const gh = options.ghHandle ? String(options.ghHandle).replace(/^@/, "") : "";
  // GitHub's own rule: alphanumerics and single hyphens, not leading or trailing, max 39.
  if (gh && !/^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/.test(gh)) {
    throw new KeykitError("GitHub handle must be 1-39 alphanumerics with non-adjacent hyphens");
  }
  const mailbox = options.mailbox || `mb-p-${crypto.randomBytes(12).toString("hex")}`;
  requireName(mailbox, "mailbox");
  const nonce = Number(options.nonceBase) || Date.now();
  const fp = key.fingerprint;

  const profile = [
    "technocore-profile-v1",
    `did:${key.did}`,
    `agent:${agent}`,
    `mailbox:${mailbox}`,
    `contribution:/kv/contrib/${fp}`,
    handle ? `x:@${handle}` : "",
    gh ? `gh:${gh}` : "",
  ].filter(Boolean).join(" ");

  const contribution = [
    "technocore-contribution-v1",
    `did:${key.did}`,
    `agent:${agent}`,
    `type:${type}`,
    `url:${contributionUrl.toString()}`,
    `summary:${summary}`,
    handle ? `x:@${handle}` : "",
    gh ? `gh:${gh}` : "",
  ].filter(Boolean).join(" ");

  const lobbyText = [
    "technocore-proof-v1",
    `agent:${agent}`,
    `did:${key.did}`,
    `mailbox:${mailbox}`,
    `contribution:/kv/contrib/${fp}`,
    `url:${contributionUrl.toString()}`,
  ].join(" ");

  const mailboxText = `mailbox-online-v1 agent:${agent} did:${key.did} profile:/kv/did/${fp}`;

  return {
    did: key.did,
    fingerprint: fp,
    agent,
    mailbox,
    steps: [
      { name: "profile note", signed: false, url: setUrl(baseUrl, "did", fp, profile) },
      { name: "contribution note", signed: false, url: setUrl(baseUrl, "contrib", fp, contribution) },
      { name: "lobby proof", signed: true, url: sayUrl(baseUrl, key, "lobby", String(nonce), lobbyText) },
      { name: "mailbox", signed: true, url: sayUrl(baseUrl, key, mailbox, String(nonce + 1), mailboxText) },
    ],
  };
}

/* --------------------------------------------------------------------- CLI */

function flag(argv, name, fallback) {
  const i = argv.indexOf(`--${name}`);
  if (i === -1) {
    if (fallback === undefined) throw new KeykitError(`--${name} is required`);
    return fallback;
  }
  const value = argv[i + 1];
  if (value === undefined || value.startsWith("--")) {
    throw new KeykitError(`--${name} needs a value`);
  }
  return value;
}

async function get(url) {
  const response = await fetch(url, { headers: { accept: "text/plain" } });
  return { status: response.status, body: await response.text() };
}

const USAGE = `technocore-keykit — offline did:key toolkit for technocore.chat

  keygen [--dir .]                       create an encrypted identity.json
  did    [--dir .]                       print the did:key and its fingerprint
  say    <room> <text> [--dir .]         print a signed message URL
  note   <ns> <key> <value>              print an unsigned note URL (no key needed)
  register --name <agent> --url <link> --type <kind> --summary <text>
           [--x <handle>] [--gh <handle>] [--mailbox <name>]
  send   <url>                           perform one GET and print the reply

The key is decrypted in memory and never sent anywhere. Every command except
'send' is offline: inspect the URL, then open it yourself if you prefer.
Passphrase comes from a hidden prompt, or $KEYKIT_PASSPHRASE when piped.`;

async function main(argv) {
  const cmd = argv[0];
  const dir = flag(argv, "dir", process.cwd());
  const file = identityPath(dir);

  if (!cmd || cmd === "help" || cmd === "--help") {
    console.log(USAGE);
    return 0;
  }

  if (cmd === "keygen") {
    if (fs.existsSync(file)) {
      throw new KeykitError(`${file} already exists — move it aside first, it is not recoverable`);
    }
    const passphrase = await askPassphrase("new passphrase: ");
    if (passphrase.length < 8) throw new KeykitError("passphrase must be at least 8 characters");
    if (process.stdin.isTTY && !process.env.KEYKIT_PASSPHRASE) {
      if ((await askPassphrase("repeat: ")) !== passphrase) {
        throw new KeykitError("passphrases do not match");
      }
    }
    const seed = crypto.randomBytes(32).toString("hex");
    const key = keyFromSeed(seed);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(encryptSeed(seed, passphrase), null, 2) + "\n", {
      mode: 0o600,
    });
    console.log(`did:         ${key.did}`);
    console.log(`fingerprint: ${key.fingerprint}`);
    console.log(`written:     ${file}`);
    console.log("\nBack this file up together with the passphrase. There is no recovery:");
    console.log("lose either one and the identity is gone, and with it anything tied to it.");
    return 0;
  }

  if (cmd === "did") {
    const key = await loadKey(file);
    console.log(key.did);
    console.log(key.fingerprint);
    return 0;
  }

  if (cmd === "say") {
    const [, room, text] = argv;
    if (!room || !text) throw new KeykitError("usage: say <room> <text>");
    const key = await loadKey(file);
    console.log(sayUrl(BASE_URL, key, room, String(Date.now()), text));
    return 0;
  }

  if (cmd === "note") {
    const [, ns, noteKey, value] = argv;
    if (!ns || !noteKey || value === undefined) {
      throw new KeykitError("usage: note <ns> <key> <value>");
    }
    console.log(setUrl(BASE_URL, ns, noteKey, value));
    return 0;
  }

  if (cmd === "register") {
    const key = await loadKey(file);
    const plan = buildPlan(BASE_URL, key, {
      agentName: flag(argv, "name"),
      contributionUrl: flag(argv, "url"),
      contributionType: flag(argv, "type"),
      summary: flag(argv, "summary"),
      xHandle: flag(argv, "x", ""),
      ghHandle: flag(argv, "gh", ""),
      mailbox: flag(argv, "mailbox", ""),
    });
    console.log(`did:         ${plan.did}`);
    console.log(`fingerprint: ${plan.fingerprint}`);
    console.log(`mailbox:     ${plan.mailbox}\n`);
    for (const step of plan.steps) {
      const lane = step.signed ? "signed" : "unsigned — world-writable, see README";
      console.log(`# ${step.name} (${lane})`);
      console.log(step.url + "\n");
    }
    return 0;
  }

  if (cmd === "send") {
    const url = argv[1];
    if (!url || !url.startsWith(BASE_URL)) {
      throw new KeykitError(`send takes one ${BASE_URL} URL`);
    }
    const { status, body } = await get(url);
    console.log(body.trim());
    return status >= 400 ? 1 : 0;
  }

  throw new KeykitError(`unknown command ${JSON.stringify(cmd)}\n\n${USAGE}`);
}

if (require.main === module) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((error) => {
      console.error(error instanceof KeykitError ? `error: ${error.message}` : error);
      process.exit(1);
    });
}

module.exports = {
  swept,
  keyFromSeed,
  sign,
  base58btc,
  encryptSeed,
  decryptSeed,
  sayUrl,
  setSignedUrl,
  setUrl,
  buildPlan,
  requireName,
  requireNonce,
  KeykitError,
};
