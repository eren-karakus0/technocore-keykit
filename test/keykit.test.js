"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const kit = require("../keykit.js");

// A fixed vector, cross-checked against the server's own signer
// (flop-labs/technocore-chat scripts/sign.py) — see test/cross-check.sh.
//
// THIS SEED IS PUBLIC AND BURNED. It is committed here on purpose so the vector
// is reproducible; anyone reading this file holds the key. Never use it for an
// identity you care about — `keygen` is the only thing that should make one.
const SEED = "b200dfecd26265ab84ef9686528036eb912b8cb7811fd6a1cead0656791f2434";
const DID = "did:key:z6MkmwirokQCTJMegqY7fET2j9euZ9kirNKiUkKYvvvQRcaj";
const FINGERPRINT = "f53c39b03c42dfd9";

test("did:key derivation matches the reference vector", () => {
  const key = kit.keyFromSeed(SEED);
  assert.equal(key.did, DID);
  assert.equal(key.fingerprint, FINGERPRINT);
  assert.equal(key.did.length, "did:key:".length + 48);
});

test("keyFromSeed rejects anything that is not 32 hex bytes", () => {
  for (const bad of ["", "zz", SEED.slice(0, 63), SEED + "aa", "not hex at all"]) {
    assert.throws(() => kit.keyFromSeed(bad), kit.KeykitError);
  }
});

test("base58btc keeps one leading '1' per leading zero byte", () => {
  assert.equal(kit.base58btc(Buffer.from([0])), "1");
  assert.equal(kit.base58btc(Buffer.from([0, 0, 1])), "112");
});

test("signatures are 86 base64url characters and verify against the public key", () => {
  const key = kit.keyFromSeed(SEED);
  const sig = kit.sign(key.privateKey, "lobby|1|hello");
  assert.equal(sig.length, 86);
  assert.match(sig, /^[A-Za-z0-9_-]{86}$/);
  const ok = crypto.verify(
    null,
    Buffer.from("lobby|1|hello", "utf8"),
    crypto.createPublicKey(key.privateKey),
    Buffer.from(sig, "base64url"),
  );
  assert.equal(ok, true);
});

test("the sweep replaces invisibles with spaces and trims, without collapsing runs", () => {
  // The server does exactly this and no more (src/store.py clean_text); collapsing
  // whitespace here would sign a different string than the one it stores.
  assert.equal(kit.swept("  hi  there  ", 4096), "hi  there");
  assert.equal(kit.swept("a​b", 4096), "a b"); // ZWSP is Cf
  assert.equal(kit.swept("a b", 4096), "a b"); // line separator is Zl
  assert.equal(kit.swept("a\tb", 4096), "a b"); // tab is Cc
});

test("the sweep refuses what the server would refuse", () => {
  assert.throws(() => kit.swept("​​", 4096), kit.KeykitError); // nothing visible left
  assert.throws(() => kit.swept("x".repeat(4097), 4096), kit.KeykitError); // over the cap
});

test("names and nonces are validated against the server's patterns", () => {
  assert.equal(kit.requireName("mb-p-abc123", "room"), "mb-p-abc123");
  assert.throws(() => kit.requireName("-leading", "room"), kit.KeykitError);
  assert.throws(() => kit.requireName("Upper", "room"), kit.KeykitError);
  assert.throws(() => kit.requireName("x".repeat(49), "room"), kit.KeykitError);
  assert.equal(kit.requireNonce("1"), "1");
  assert.throws(() => kit.requireNonce("١٢٣"), kit.KeykitError); // Unicode digits, not ASCII
  assert.throws(() => kit.requireNonce("1".repeat(20)), kit.KeykitError);
});

test("an encrypted identity round-trips, and a wrong passphrase fails closed", () => {
  const blob = kit.encryptSeed(SEED, "correct horse battery");
  assert.equal(blob.cipher, "aes-256-gcm");
  assert.ok(!JSON.stringify(blob).includes(SEED), "the seed must not appear in the blob");
  assert.equal(kit.decryptSeed(blob, "correct horse battery"), SEED);
  assert.throws(() => kit.decryptSeed(blob, "wrong"), kit.KeykitError);
});

test("a tampered ciphertext is rejected by the GCM tag", () => {
  const blob = kit.encryptSeed(SEED, "passphrase123");
  const bytes = Buffer.from(blob.ciphertext, "base64");
  bytes[0] ^= 0xff;
  blob.ciphertext = bytes.toString("base64");
  assert.throws(() => kit.decryptSeed(blob, "passphrase123"), kit.KeykitError);
});

test("sayUrl signs the swept text, not the raw text", () => {
  const key = kit.keyFromSeed(SEED);
  const url = kit.sayUrl("https://example.test", key, "lobby", "7", "  a​b  ");
  const sig = url.split("/say-signed/")[1].split("/")[1];
  const ok = crypto.verify(
    null,
    Buffer.from("lobby|7|a b", "utf8"), // swept, not raw
    crypto.createPublicKey(key.privateKey),
    Buffer.from(sig, "base64url"),
  );
  assert.equal(ok, true);
  assert.ok(url.endsWith("/a%20b"));
});

test("buildPlan marks the note lanes unsigned and the room lanes signed", () => {
  const key = kit.keyFromSeed(SEED);
  const plan = kit.buildPlan("https://example.test", key, {
    agentName: "test-agent",
    contributionUrl: "https://github.com/example/repo",
    contributionType: "tool",
    summary: "A test contribution.",
    nonceBase: 1000,
  });
  const byName = Object.fromEntries(plan.steps.map((s) => [s.name, s]));
  assert.equal(byName["profile note"].signed, false);
  assert.equal(byName["contribution note"].signed, false);
  assert.equal(byName["lobby proof"].signed, true);
  assert.equal(byName["mailbox"].signed, true);
  assert.match(plan.mailbox, /^mb-p-[0-9a-f]{24}$/);
  // Nonces must count up per key per room; the two signed writes are in
  // different rooms, but keeping them distinct costs nothing and survives a
  // caller that reuses the mailbox name as the lobby room.
  assert.ok(byName["lobby proof"].url.includes("/1000/"));
  assert.ok(byName["mailbox"].url.includes("/1001/"));
});

test("buildPlan carries the X and GitHub handles into both notes", () => {
  const key = kit.keyFromSeed(SEED);
  const plan = kit.buildPlan("https://example.test", key, {
    agentName: "test-agent",
    contributionUrl: "https://github.com/example/repo",
    contributionType: "tool",
    summary: "A test contribution.",
    xHandle: "@SomeHandle",
    ghHandle: "some-user",
  });
  for (const name of ["profile note", "contribution note"]) {
    const url = decodeURIComponent(plan.steps.find((s) => s.name === name).url);
    assert.match(url, /x:@SomeHandle\b/); // the leading @ is stripped, then re-added once
    assert.match(url, /gh:some-user\b/);
  }
});

test("buildPlan rejects malformed handles", () => {
  const key = kit.keyFromSeed(SEED);
  const base = {
    agentName: "test-agent",
    contributionUrl: "https://github.com/example/repo",
    contributionType: "tool",
    summary: "A test contribution.",
  };
  for (const xHandle of ["way-too-long-for-x-handle", "has space", "has-hyphen"]) {
    assert.throws(() => kit.buildPlan("https://example.test", key, { ...base, xHandle }), kit.KeykitError);
  }
  for (const ghHandle of ["-leading", "trailing-", "double--hyphen", "x".repeat(40)]) {
    assert.throws(() => kit.buildPlan("https://example.test", key, { ...base, ghHandle }), kit.KeykitError);
  }
});

test("buildPlan rejects a contribution that is not a real http(s) URL", () => {
  const key = kit.keyFromSeed(SEED);
  const base = {
    agentName: "test-agent",
    contributionType: "tool",
    summary: "A test contribution.",
  };
  assert.throws(
    () => kit.buildPlan("https://example.test", key, { ...base, contributionUrl: "not a url" }),
    TypeError, // URL() rejects it before we do
  );
  assert.throws(
    () =>
      kit.buildPlan("https://example.test", key, {
        ...base,
        contributionUrl: "file:///etc/passwd",
      }),
    kit.KeykitError,
  );
  assert.throws(
    () =>
      kit.buildPlan("https://example.test", key, {
        ...base,
        contributionUrl: "https://ok.test",
        contributionType: "shilling",
      }),
    kit.KeykitError,
  );
});
