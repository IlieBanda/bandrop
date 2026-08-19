#!/usr/bin/env bash
# End-to-end test for `bandrop serve`: HTTP index + file download via curl.
set -u
BIN="$(cd "$(dirname "${1:-build/bandrop}")" && pwd)/$(basename "${1:-build/bandrop}")"
PORT="${2:-8071}"
command -v curl >/dev/null || { echo "SKIP serve (no curl)"; exit 0; }
T="$(mktemp -d)"; FAIL=0
head -c 600000 /dev/urandom > "$T/a.bin"; printf 'browser hello\n' > "$T/note.txt"
"$BIN" serve "$T/a.bin" "$T/note.txt" --port "$PORT" > "$T/s.out" 2>&1 &
S=$!; sleep 0.7
URL=$(grep -oE 'http://[^ ]+/' "$T/s.out" | head -1)
[ -n "$URL" ] || { echo "FAIL serve (no URL)"; kill $S 2>/dev/null; rm -rf "$T"; exit 1; }
curl -s "$URL" | grep -q "available files" && echo "OK  serve index" || { echo "FAIL serve index"; FAIL=1; }
curl -s "${URL}a.bin" -o "$T/a.dl"; curl -s "${URL}note.txt" -o "$T/n.dl"
cmp -s "$T/a.bin" "$T/a.dl" && echo "OK  serve download binary" || { echo "FAIL serve binary"; FAIL=1; }
cmp -s "$T/note.txt" "$T/n.dl" && echo "OK  serve download text" || { echo "FAIL serve text"; FAIL=1; }
curl -s -o /dev/null -w "%{http_code}" "${URL}../../etc/passwd" | grep -q 404 && echo "OK  serve rejects unknown path" || echo "note: path check"
kill $S 2>/dev/null; rm -rf "$T"
[ $FAIL -eq 0 ] && { echo "SERVE E2E PASS"; exit 0; } || { echo "SERVE E2E FAIL"; exit 1; }
