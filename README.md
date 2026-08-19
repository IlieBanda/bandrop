# 🚀 Bandrop

**Bandrop** is a fast, secure, lightweight P2P file transfer CLI written in C++.

Inspired by *Magic Wormhole* and *AirDrop*, Bandrop securely sends files across
your local network using a simple 6-digit pairing code. No cloud servers, no
accounts, no tracking.

## ✨ Features

- **Authenticated encryption over a framed protocol.** Files are streamed as
  length-prefixed **AES-256-CBC** messages, each with a fresh random IV. Because
  every message is framed, transfers stay correct over TCP regardless of how the
  stream is chunked.
- **PIN-based pairing with a real KDF.** The sender shows a random 6-digit PIN.
  The key is derived from that PIN and a per-session random salt using
  **PBKDF2-HMAC-SHA256** (200k iterations) — the PIN itself never crosses the wire.
- **Wrong-PIN detection.** A bad code fails the padding check on the first frame,
  so the receiver reports the error and cleans up instead of writing garbage.
- **Robust I/O.** Full send/recv loops, socket and file error handling, filename
  sanitization (basename only — no path traversal), progress bar, and human-readable
  sizes.
- **Minimal dependencies.** POSIX sockets and OpenSSL only.

## 🛠️ Build

```bash
git clone https://github.com/IlieBanda/bandrop.git
cd bandrop
cmake -S . -B build
cmake --build build
```

The binary is produced at `build/bandrop`.

## 📖 Usage

### Receiver
```bash
./build/bandrop receive              # default port 9090
./build/bandrop receive --port 8080
```
It waits for a sender, then prompts for the 6-digit pairing code.

### Sender
```bash
./build/bandrop send <ip> <file> [--port <port>]
# e.g.
./build/bandrop send 192.168.1.42 ~/video.mp4
```
Bandrop prints a 6-digit code — share it with the receiver to complete the transfer.

## 🔒 Security notes

A 6-digit PIN has ~20 bits of entropy, so Bandrop is designed for trusted local
networks. The PBKDF2 work factor slows brute force, but the pairing model assumes
the receiver only accepts a connection they are expecting. It is not a replacement
for an authenticated key exchange over a hostile network.

---
*Built with ❤️ by Ilia Banda*
