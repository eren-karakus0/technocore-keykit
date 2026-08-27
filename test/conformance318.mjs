// Run the conformance vectors from flop-labs/technocore-chat#318 against keykit.
//
// A different shape from #314's: text is carried as code-point arrays, because the swept
// set includes characters with no UTF-8 encoding, and the file adds identities, rejected
// DID shapes and the 16 accepted spellings of one signature.
//
//   node test/conformance318.mjs path/to/vectors.json

import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { verify as edVerify, createPublicKey } from "node:crypto";

const require = createRequire(import.meta.url);
const kit = require("../keykit.js");

const path = process.argv[2];
if (!path) {
  console.error("usage: node test/conformance318.mjs <vectors.json>");
  process.exit(2);
}
const vectors = JSON.parse(readFileSync(path, "utf8"));

let pass = 0;
let fail = 0;
const bad = [];
const check = (label, expected, actual) => {
  if (expected === actual) {
    pass += 1;
    return true;
  }
  fail += 1;
  bad.push(`${label}\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`);
  return false;
};

const fromCodePoints = (points) => String.fromCodePoint(...points);
const toCodePoints = (text) => Array.from(text, (c) => c.codePointAt(0));

console.log(`provenance: Unicode ${vectors.provenance.unicode_version}, categories ` +
  `${vectors.provenance.invisible_categories.join("")}`);

console.log(`\n=== ${vectors.sweep_cases.length} sweep cases ===`);
for (const vector of vectors.sweep_cases) {
  const input = fromCodePoints(vector.in_cp);
  let actual;
  try {
    actual = toCodePoints(kit.swept(input, vectors.provenance.max_text_chars));
  } catch (error) {
    // The server refuses a text the sweep empties; the fixture marks those.
    if (vector.raises_empty) {
      pass += 1;
      console.log(`  ok   ${vector.name} (refused, as marked)`);
      continue;
    }
    fail += 1;
    bad.push(`${vector.name}: threw unexpectedly — ${error.message}`);
    continue;
  }
  if (vector.raises_empty) {
    fail += 1;
    bad.push(`${vector.name}: should have been refused as empty, returned ${JSON.stringify(actual)}`);
    continue;
  }
  const ok = check(`${vector.name}`, JSON.stringify(vector.out_cp), JSON.stringify(actual));
  if (ok) console.log(`  ok   ${vector.name}${vector.version_sensitive ? "  (version-sensitive)" : ""}`);
}

console.log(`\n=== ${vectors.identities.length} identities ===`);
for (const identity of vectors.identities) {
  const key = kit.keyFromSeed(identity.seed_hex);
  const okDid = check(`did for ${identity.seed_hex.slice(0, 8)}…`, identity.did, key.did);
  const okFp = check(`fingerprint for ${identity.seed_hex.slice(0, 8)}…`, identity.fingerprint, key.fingerprint);
  if (okDid && okFp) console.log(`  ok   ${identity.fingerprint}  ${identity.did.slice(0, 26)}…`);
}

console.log(`\n=== ${vectors.did_invalid.length} rejected DID shapes ===`);
for (const vector of vectors.did_invalid) {
  let threw = false;
  try {
    kit.fingerprintOf(vector.did);
  } catch {
    threw = true;
  }
  if (threw) {
    pass += 1;
    console.log(`  ok   rejected: ${vector.why}`);
  } else {
    fail += 1;
    bad.push(`accepted a DID it should reject (${vector.why}): ${vector.did}`);
  }
}

console.log(`\n=== ${vectors.signature_cases.length} signature cases ===`);
for (const vector of vectors.signature_cases) {
  const key = kit.keyFromSeed(vector.seed_hex);
  const swept = fromCodePoints(vector.text_swept_cp);
  const payload = `${vector.room}|${vector.nonce}|${swept}`;
  check(`${vector.name} payload`, vector.payload_display, payload);
  const produced = kit.sign(key.privateKey, payload);
  const okSig = check(`${vector.name} signature`, vector.sig_canonical, produced);

  // The claim this fixture adds: the server accepts 16 spellings of the same 64 bytes,
  // because 86 unpadded base64url characters carry 4 bits more than the signature needs.
  const publicKey = createPublicKey(key.privateKey);
  const message = Buffer.from(payload, "utf8");
  const verified = vector.sig_accepted_spellings.filter((spelling) =>
    edVerify(null, message, publicKey, Buffer.from(spelling, "base64url")),
  ).length;
  const okSpellings = check(
    `${vector.name} accepted spellings`,
    vector.sig_accepted_spellings.length,
    verified,
  );
  if (okSig && okSpellings) {
    console.log(`  ok   ${vector.name}  (${verified}/${vector.sig_accepted_spellings.length} spellings verify)`);
  }
}

console.log(`\n${fail ? `${fail} FAILURE(S), ${pass} passed` : `all ${pass} checks pass`} — node ${process.version}`);
for (const line of bad) console.log(`  FAIL ${line}`);
process.exit(fail ? 1 : 0);
