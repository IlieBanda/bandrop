# 🚀 Bandrop

**Bandrop** is a fast, secure, zero-config P2P file & folder transfer CLI
written in modern C++. Think *Magic Wormhole* meets *AirDrop*: pair two
machines on your LAN with a short code and move files directly between them —
no cloud, no accounts, no size limits, no tracking.

## ✨ Highlights

- **Password-authenticated key exchange (SPAKE2, RFC 9382 over P-256).**
  The sender shows a random 6-digit code. Both sides run SPAKE2 to agree on a
  session key — the PIN and the key never touch the wire, and there's no
  transcript an eavesdropper or man-in-the-middle can brute-force the PIN
  against offline. A wrong code fails key confirmation and the transfer aborts
  *before any file data is exchanged*.
- **Authenticated encryption (AES-256-GCM).** Every framed message carries a
  fresh nonce and an authentication tag, so tampering and truncation are
  detected on the fly.
- **End-to-end integrity.** Each file's SHA-256 is verified on arrival.
- **Zero-config LAN discovery.** Receivers advertise themselves over UDP; the
  sender finds them automatically — no IP typing required.
- **Files *and* folders.** Send whole directory trees; structure is preserved
  and untrusted paths are sanitized (no path traversal).
- **On-the-fly compression** (optional, zlib).
- **Live progress** with transfer rate and ETA.

## 🛠️ Build

Requires a C++17 compiler, CMake, OpenSSL and zlib.

```bash
# Debian/Ubuntu: sudo apt-get install cmake g++ libssl-dev zlib1g-dev
cmake -S . -B build
cmake --build build
```

The binary lands at `build/bandrop`. Run the tests with `ctest --test-dir build`.

## 📖 Usage

### Receive
```bash
./build/bandrop receive                 # waits, and announces itself on the LAN
./build/bandrop receive --out ~/Inbox   # save into a directory
./build/bandrop receive --port 8080 --no-announce
```
The receiver prints a prompt; type the 6-digit code shown by the sender.

### Send
```bash
# Auto-discover the receiver on the LAN (no IP needed):
./build/bandrop send report.pdf ~/photos

# Or target a specific host:
./build/bandrop send bigfile.iso --to 192.168.1.42

# Compress on the way:
./build/bandrop send logs/ --compress
```
Bandrop prints a **pairing code** — read it out to the person receiving.

### Discover
```bash
./build/bandrop discover     # list receivers currently waiting on the LAN
```

## 🔒 Security model

Bandrop uses SPAKE2, so a 6-digit code is enough: an active attacker gets only
**one online guess per connection** and learns nothing to attack offline.
Confidentiality and integrity in transit come from AES-256-GCM keyed by the
SPAKE2 session key, and each file is SHA-256-verified end to end.

That said, this is a compact utility, not an audited security product. The
threat model is a trusted user moving files across a local network; it is not a
substitute for a reviewed, hardened transport in a hostile environment.

## 🧩 Layout

| File | Responsibility |
|------|----------------|
| `crypto.h` | AES-256-GCM, HKDF, HMAC, SHA-256, RNG |
| `spake2.h` | SPAKE2 password-authenticated key exchange |
| `session.h` | Sealed, length-framed message channel |
| `protocol.h` | Framing, (de)serialization, path hygiene |
| `net.h` | TCP connect/listen helpers |
| `discovery.h` | UDP broadcast peer discovery |
| `archive.h` | Directory walking & path reconstruction |
| `compress.h` | Optional zlib chunk compression |
| `ui.h` | Progress bar, rate/ETA, human sizes |
| `sender.h` / `receiver.h` | Transfer orchestration |

---
*Built with ❤️ by Ilia Banda*
