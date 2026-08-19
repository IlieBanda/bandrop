# Bandrop — notes for Claude

Secure, zero-config P2P transfer CLI in C++17. Single binary, header-only
modules, no server/relay anywhere (all direct peer-to-peer).

## Build & test
- `cmake -S . -B build && cmake --build build` → `build/bandrop`
- `ctest --test-dir build` runs `tests/selftest.cpp` (crypto, SPAKE2, QR, JSON, receipts).
- E2E scripts in `tests/`: `e2e.sh` (files), `pipe_e2e.sh`, `serve_e2e.sh`,
  `receipt_e2e.sh`. Each takes `<binary> <port>`.
- Deps: OpenSSL, zlib, pthreads. Version lives in `version.h` (and CMake/Formula).

## Architecture
- Pairing: SPAKE2 (`spake2.h`) driven by `handshake.h` (initiator/responder).
- Transport: `session.h` seals typed messages with AES-256-GCM and length-frames
  them (`protocol.h`). Message types in `proto::MsgType`.
- Modes: `sender.h`/`receiver.h` (files+folders, receipts), `pipe.h` (stdin↔stdout),
  `serve.h` (HTTP+QR). Wired in `main.cpp` subcommands.
- Discovery: `discovery.h` (UDP broadcast). Identity/receipts: `identity.h`
  (Ed25519), `receipt.h` + `json.h`. QR: `qr.h` (verified against Python `qrcode`
  in `tests/qr_verify.py`; golden vectors in the unit test).

## Conventions
- Keep it header-only and dependency-light. Add unit coverage to `selftest.cpp`
  and an e2e script for anything protocol-facing.
- stdout is block-buffered when redirected — `std::flush` after prompts/URLs that
  precede a blocking wait, or tests deadlock.
- Don't add a relay/cloud component; direct P2P is a core design constraint.
