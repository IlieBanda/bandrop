#!/usr/bin/env bash
# End-to-end resume: transfer a folder, delete part of it, resend with --resume
# and confirm only the missing files move and everything ends up correct.
set -u
BIN="$(cd "$(dirname "${1:-build/bandrop}")" && pwd)/$(basename "${1:-build/bandrop}")"
PORT="${2:-9300}"
export HOME="$(mktemp -d)"
T="$(mktemp -d)"; mkdir -p "$T/src/sub" "$T/dst"; FAIL=0
head -c 250000 /dev/urandom > "$T/src/a.bin"
head -c 180000 /dev/urandom > "$T/src/sub/b.bin"
head -c 120000 /dev/urandom > "$T/src/c.bin"

send() { # port flags
  local p="$1" flags="$2"
  mkfifo "$T/pin$p"; exec 9<>"$T/pin$p"
  ( cd "$T/dst" && exec "$BIN" receive --port "$p" <&9 > "$T/r$p.out" 2>&1 ) & local R=$!
  sleep 0.4
  "$BIN" send "$T/src" --to 127.0.0.1 --port "$p" $flags > "$T/s$p.out" 2>&1 & local S=$!
  local PIN=""; for i in $(seq 1 60); do PIN=$(grep -oE 'CODE:  ?[0-9]+' "$T/s$p.out"|grep -oE '[0-9]+'); [ -n "$PIN" ]&&break; sleep 0.1; done
  printf '%s\n' "$PIN" >&9; wait $S; wait $R; exec 9>&-; rm -f "$T/pin$p"
}

send "$PORT" ""
rm -f "$T/dst/src/a.bin" "$T/dst/src/sub/b.bin"
send "$((PORT+1))" "--resume"
grep -q "needs 2 of 3" "$T/s$((PORT+1)).out" && echo "OK  resume sends only missing files" || { echo "FAIL resume count"; FAIL=1; }
for f in src/a.bin src/sub/b.bin src/c.bin; do
  cmp -s "$T/${f/src/src}" "$T/dst/$f" 2>/dev/null || cmp -s "$T/src/${f#src/}" "$T/dst/$f" || { echo "FAIL $f"; FAIL=1; }
done
[ $FAIL -eq 0 ] && echo "OK  all files correct after resume"
rm -rf "$T" "$HOME"
[ $FAIL -eq 0 ] && { echo "RESUME E2E PASS"; exit 0; } || { echo "RESUME E2E FAIL"; exit 1; }
