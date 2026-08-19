#!/usr/bin/env bash
# End-to-end: transfer with a signed receipt, then verify it (and detect tamper).
set -u
BIN="$(cd "$(dirname "${1:-build/bandrop}")" && pwd)/$(basename "${1:-build/bandrop}")"
PORT="${2:-9130}"
export HOME="$(mktemp -d)"   # isolated identity keystore
T="$(mktemp -d)"; mkdir -p "$T/d"; FAIL=0
head -c 80000 /dev/urandom > "$T/f1.bin"; printf 'hello receipt\n' > "$T/f2.txt"
mkfifo "$T/pin"; exec 8<>"$T/pin"
( cd "$T/d" && exec "$BIN" receive --port "$PORT" --receipt receipt.json <&8 > "$T/recv.out" 2>&1 ) & R=$!
sleep 0.5
"$BIN" send "$T/f1.bin" "$T/f2.txt" --to 127.0.0.1 --port "$PORT" > "$T/send.out" 2>&1 & S=$!
PIN=""; for i in $(seq 1 60); do PIN=$(grep -oE 'CODE:  ?[0-9]+' "$T/send.out"|grep -oE '[0-9]+'); [ -n "$PIN" ]&&break; sleep 0.1; done
printf '%s\n' "$PIN" >&8; wait $S; wait $R; exec 8>&-
grep -q "verified" "$T/recv.out" && echo "OK  receipt verified on receive" || { echo "FAIL receipt on receive"; FAIL=1; }
"$BIN" verify "$T/d/receipt.json" >/dev/null 2>&1 && echo "OK  bandrop verify accepts receipt" || { echo "FAIL verify"; FAIL=1; }
sed 's/"size": 80000/"size": 1/' "$T/d/receipt.json" > "$T/bad.json"
"$BIN" verify "$T/bad.json" >/dev/null 2>&1 && { echo "FAIL tamper not detected"; FAIL=1; } || echo "OK  verify rejects tampered receipt"
rm -rf "$T" "$HOME"
[ $FAIL -eq 0 ] && { echo "RECEIPT E2E PASS"; exit 0; } || { echo "RECEIPT E2E FAIL"; exit 1; }
