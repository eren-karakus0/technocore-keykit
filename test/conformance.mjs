// Run flop-labs/technocore-chat's published conformance vectors (PR #314) against keykit.
//
// The fixture is generated from the server's own `store.clean_text` and signer, so it is the
// authoritative statement of the sweep, the canonical string and the signature encoding. This
// consumes it the way a client in any language would: derive the same key, sweep the same
// text, rebuild the same canonical string, and compare all three plus the 86 characters.
//
//   node test/conformance.mjs path/to/vectors.json

import { createRequire } from "node:module";
import { readFileSync } from "node:fs";

const require = createRequire(import.meta.url);
const kit = require("../keykit.js");

const path = process.argv[2];
if (!path) {
  console.error("usage: node test/conformance.mjs <vectors.json>");
  process.exit(2);
}

const vectors = JSON.parse(readFileSync(path, "utf8"));

// The fixture names the seed as one repeated byte rather than 64 hex characters.
const seed = Buffer.alloc(32, vectors.seed_byte).toString("hex");
const key = kit.keyFromSeed(seed);

let failures = 0;
const check = (label, expected, actual) => {
  const ok = expected === actual;
  if (!ok) {
    failures += 1;
    console.log(`  FAIL ${label}`);
    console.log(`       expected ${JSON.stringify(expected)}`);
    console.log(`       actual   ${JSON.stringify(actual)}`);
  }
  return ok;
};

console.log("=== identity ===");
check("did", vectors.did, key.did);
check("fingerprint", vectors.fingerprint, key.fingerprint);
console.log(`  did         ${key.did}`);
console.log(`  fingerprint ${key.fingerprint}`);

console.log(`\n=== ${vectors.messages.length} message vectors ===`);
for (const [index, vector] of vectors.messages.entries()) {
  const swept = kit.swept(vector.text, 4096);
  const canonical = `${vector.room}|${vector.nonce}|${swept}`;
  const sig = kit.sign(key.privateKey, canonical);
  const ok =
    check(`[${index}] swept`, vector.swept, swept) &&
    check(`[${index}] canonical`, vector.canonical, canonical) &&
    check(`[${index}] sig`, vector.sig, sig);
  if (ok) console.log(`  ok  [${index}] ${JSON.stringify(vector.text).slice(0, 52)}`);
}

console.log("\n=== 1 note vector ===");
const note = vectors.note;
const noteSwept = kit.swept(note.value, 8192);
const noteCanonical = `${note.ns}|${note.key}|${note.nonce}|${noteSwept}`;
const noteSig = kit.sign(key.privateKey, noteCanonical);
if (
  check("note swept", note.swept, noteSwept) &&
  check("note canonical", note.canonical, noteCanonical) &&
  check("note sig", note.sig, noteSig)
) {
  console.log(`  ok  ${note.ns}/${note.key}`);
}

const total = vectors.messages.length * 3 + 5;
console.log(
  `\n${failures ? `${failures} MISMATCH(ES)` : `all ${total} checks pass`} ` +
    `— node ${process.version}`,
);
process.exit(failures ? 1 : 0);
