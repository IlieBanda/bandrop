#!/usr/bin/env bash
# End-to-end: one broadcaster fans out to two receivers with a single code.
set -u
BIN="$(cd "$(dirname "${1:-build/bandrop}")" && pwd)/$(basename "${1:-build/bandrop}")"
PORT="${2:-9220}"
export HOME="$(mktemp -d)"
T="$(mktemp -d)"; mkdir -p "$T/r1" "$T/r2"; FAIL=0
head -c 500000 /dev/urandom > "$T/p.bin"
"$BIN" broadcast "$T/p.bin" --port "$PORT" > "$T/b.out" 2>&1 & B=$!; sleep 0.6
CODE=$(grep -oE 'CODE:  ?[0-9]+' "$T/b.out" | grep -oE '[0-9]+')
[ -n "$CODE" ] || { echo "FAIL broadcast (no code)"; kill $B 2>/dev/null; rm -rf "$T" "$HOME"; exit 1; }
( cd "$T/r1" && echo "$CODE" | "$BIN" receive --from 127.0.0.1 --port "$PORT" >/dev/null 2>&1 ) & R1=$!
( cd "$T/r2" && echo "$CODE" | "$BIN" receive --from 127.0.0.1 --port "$PORT" >/dev/null 2>&1 ) & R2=$!
wait $R1; wait $R2; sleep 0.2; kill $B 2>/dev/null
cmp -s "$T/p.bin" "$T/r1/p.bin" && echo "OK  broadcast receiver 1" || { echo "FAIL r1"; FAIL=1; }
cmp -s "$T/p.bin" "$T/r2/p.bin" && echo "OK  broadcast receiver 2" || { echo "FAIL r2"; FAIL=1; }
rm -rf "$T" "$HOME"
[ $FAIL -eq 0 ] && { echo "BROADCAST E2E PASS"; exit 0; } || { echo "BROADCAST E2E FAIL"; exit 1; }
