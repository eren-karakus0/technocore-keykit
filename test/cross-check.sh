#!/usr/bin/env bash
# Cross-implementation check: every signature this tool produces must be
# byte-identical to the one the server's own signer produces for the same input.
#
# Ed25519 is deterministic (RFC 8032), so "same key, same message" means "same
# 86 characters". Any divergence here is a bug in the canonical string or in the
# sweep — the two places where a signed write silently becomes a 403.
#
#   SIGNER=/path/to/technocore-chat/scripts/sign.py ./test/cross-check.sh
#
# Needs python with `cryptography` on PATH, and node.
set -euo pipefail

SIGNER="${SIGNER:-}"
if [ -z "$SIGNER" ] || [ ! -f "$SIGNER" ]; then
  echo "set SIGNER to technocore-chat's scripts/sign.py" >&2
  exit 2
fi

SEED="b200dfecd26265ab84ef9686528036eb912b8cb7811fd6a1cead0656791f2434"
export SIGN_SEED="$SEED"
here="$(cd "$(dirname "$0")/.." && pwd)"

fail=0
check() {
  local kind="$1" room="$2" nonce="$3" text="$4"
  local py js
  py="$(python "$SIGNER" say "$room" "$nonce" "$text" | sed -n 2p)"
  js="$(node -e '
    const kit = require(process.argv[1] + "/keykit.js");
    const key = kit.keyFromSeed(process.argv[2]);
    const url = kit.sayUrl("https://x.test", key, process.argv[3], process.argv[4], process.argv[5]);
    process.stdout.write(url.split("/say-signed/")[1].split("/")[1]);
  ' "$here" "$SEED" "$room" "$nonce" "$text")"
  if [ "$py" = "$js" ]; then
    echo "ok   $kind"
  else
    echo "FAIL $kind"
    echo "     python: $py"
    echo "     node  : $js"
    fail=1
  fi
}

check "plain ascii"        lobby 1              "hello technocore"
check "leading/inner space" lobby 2             "  spaced   out  "
check "tab becomes space"  lobby 3              "$(printf 'a\tb')"
check "punctuation"        lobby 4              "slash / colon: pipe| percent% plus+ amp&"
check "utf-8 turkish"      lobby 5              "şğüöçİı ĞÜÖÇ"
check "emoji"              lobby 6              "compute 🧠 inference"
check "long-ish nonce"     mb-p-abc 1787668339808 "mailbox-online-v1 did:key test"
check "max nonce digits"   lobby 9999999999999999999 "boundary nonce"

exit "$fail"
