#!/usr/bin/env bash
# End-to-end test: build a directory tree, transfer it with a correct PIN via
# LAN discovery, and verify every file matches byte-for-byte.
set -u
BIN="$(cd "$(dirname "${1:-build/bandrop}")" && pwd)/$(basename "${1:-build/bandrop}")"
PORT="${2:-9091}"
ROOT="$(mktemp -d)"
SRC="$ROOT/src"; DST="$ROOT/dst"
mkdir -p "$SRC/sub/deep" "$DST"

head -c 1500000 /dev/urandom > "$SRC/big.bin"
head -c 10 /dev/urandom      > "$SRC/tiny.bin"
: > "$SRC/empty.bin"
echo "hello world" > "$SRC/sub/note.txt"
head -c 300000 /dev/urandom  > "$SRC/sub/deep/data.bin"

PIN_PIPE="$ROOT/pin"; mkfifo "$PIN_PIPE"
exec 7<>"$PIN_PIPE"
( cd "$DST" && exec "$BIN" receive --port "$PORT" <&7 > "$ROOT/recv.out" 2>&1 ) &
RPID=$!
sleep 0.6

# Send via LAN discovery (no --to): exercises UDP discovery + multi-file.
"$BIN" send "$SRC/big.bin" "$SRC/sub" "$SRC/tiny.bin" "$SRC/empty.bin" \
    --port "$PORT" > "$ROOT/send.out" 2>&1 &
SPID=$!

PIN=""
for i in $(seq 1 80); do
    PIN=$(grep -oE 'PAIRING CODE:  ?[0-9]+' "$ROOT/send.out" | grep -oE '[0-9]+')
    [ -n "$PIN" ] && break; sleep 0.1
done
[ -z "$PIN" ] && { echo "NO PIN"; cat "$ROOT/send.out"; kill $SPID $RPID 2>/dev/null; exit 1; }
printf '%s\n' "$PIN" >&7
wait $SPID; SR=$?; wait $RPID; RR=$?
exec 7>&-

echo "=== send rc=$SR recv rc=$RR ==="
echo "--- send tail ---"; tail -4 "$ROOT/send.out"
echo "--- recv tail ---"; tail -4 "$ROOT/recv.out"

FAIL=0
check() { if cmp -s "$1" "$2"; then echo "OK  $3"; else echo "MISMATCH $3"; FAIL=1; fi; }
check "$SRC/big.bin"           "$DST/big.bin"           "big.bin"
check "$SRC/tiny.bin"          "$DST/tiny.bin"          "tiny.bin"
check "$SRC/empty.bin"         "$DST/empty.bin"         "empty.bin"
check "$SRC/sub/note.txt"      "$DST/sub/note.txt"      "sub/note.txt"
check "$SRC/sub/deep/data.bin" "$DST/sub/deep/data.bin" "sub/deep/data.bin"

rm -rf "$ROOT"
[ $SR -eq 0 ] && [ $RR -eq 0 ] && [ $FAIL -eq 0 ] && { echo "E2E PASS"; exit 0; }
echo "E2E FAIL"; exit 1
