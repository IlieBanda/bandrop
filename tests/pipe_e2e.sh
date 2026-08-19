#!/usr/bin/env bash
# End-to-end test for `bandrop pipe`: unidirectional and bidirectional.
set -u
BIN="$(cd "$(dirname "${1:-build/bandrop}")" && pwd)/$(basename "${1:-build/bandrop}")"
PORT="${2:-9111}"
T="$(mktemp -d)"; FAIL=0

# --- unidirectional: stream a binary through the pipe ---
head -c 1300000 /dev/urandom > "$T/in.bin"
"$BIN" pipe --listen --code 424242 --port "$PORT" < /dev/null > "$T/out.bin" 2>/dev/null &
L=$!; sleep 0.5
cat "$T/in.bin" | "$BIN" pipe --to 127.0.0.1 --code 424242 --port "$PORT" 2>/dev/null
wait $L
cmp -s "$T/in.bin" "$T/out.bin" && echo "OK  pipe unidirectional" || { echo "FAIL pipe unidirectional"; FAIL=1; }

# --- bidirectional: both sides send at once ---
head -c 700000 /dev/urandom > "$T/a.bin"
head -c 400000 /dev/urandom > "$T/b.bin"
"$BIN" pipe --listen --code 777888 --port "$((PORT+1))" < "$T/b.bin" > "$T/b_out.bin" 2>/dev/null &
L=$!; sleep 0.5
"$BIN" pipe --to 127.0.0.1 --code 777888 --port "$((PORT+1))" < "$T/a.bin" > "$T/a_out.bin" 2>/dev/null
wait $L
cmp -s "$T/a.bin" "$T/b_out.bin" && echo "OK  pipe A->B" || { echo "FAIL pipe A->B"; FAIL=1; }
cmp -s "$T/b.bin" "$T/a_out.bin" && echo "OK  pipe B->A" || { echo "FAIL pipe B->A"; FAIL=1; }

rm -rf "$T"
[ $FAIL -eq 0 ] && { echo "PIPE E2E PASS"; exit 0; } || { echo "PIPE E2E FAIL"; exit 1; }
