<h1 align="center">🚀 Bandrop</h1>
<p align="center"><b>Secure, zero-config peer-to-peer transfer for your LAN.</b><br>
Send files & folders, pipe commands between machines, or share to any browser — no cloud, no accounts, no server in the middle.</p>

---

Bandrop is a single, dependency-light C++ binary that moves data directly between
machines. Pairing is a short code; encryption is end-to-end
(**SPAKE2** + **AES-256-GCM**); discovery is automatic on the local network.
Nothing is proxied through a third party.

## Install

**One line** (Linux/macOS — builds from source, installs deps automatically):

```bash
curl -fsSL https://raw.githubusercontent.com/IlieBanda/bandrop/main/install.sh | sh
```

**Homebrew:**

```bash
brew install --HEAD IlieBanda/bandrop/bandrop     # from a tap
# or, from a local checkout:
brew install --build-from-source ./Formula/bandrop.rb
```

**From source:**

```bash
cmake -S . -B build && cmake --build build     # -> build/bandrop
sudo make install                              # -> /usr/local/bin/bandrop
```

Needs a C++17 compiler, CMake, OpenSSL and zlib.

## What it does

| Command | What it's for |
|---------|---------------|
| `bandrop send <paths…>` | Send files/folders to another machine (auto-discovers the receiver). |
| `bandrop receive` | Receive a transfer; can save a signed receipt. |
| `bandrop pipe` | A secure, paired `stdin↔stdout` pipe between two machines (netcat + ssh, zero-config). |
| `bandrop serve <paths…>` | Share files over HTTP + QR so **any browser/phone** can download — nothing to install on the other end. |
| `bandrop broadcast <paths…>` | Fan-out one set of files to **many receivers** with a single code. |
| `bandrop verify <receipt>` | Verify a signed transfer receipt offline. |
| `bandrop id` | Show your Ed25519 identity fingerprint. |
| `bandrop discover` | List receivers waiting on the LAN. |

### Send & receive

```bash
# receiver
bandrop receive                      # waits, announces itself on the LAN
bandrop receive --out ~/Inbox --receipt receipt.json

# sender (auto-discovers the receiver; or use --to <ip>)
bandrop send report.pdf ~/photos/
```

The sender shows a 6-digit code; type it on the receiver. Folders keep their
structure, existing files are auto-renamed (or `--overwrite`), every file is
SHA-256-verified, and the sender signs a receipt you can keep.

**Resume** an interrupted folder transfer — only the missing files move:

```bash
bandrop send ~/big-folder --to hostB --resume
```

### Pipe — the composable primitive

`bandrop pipe` is the killer feature: a secure, bidirectional pipe you can drop
into any Unix pipeline, across machines, with no ssh and no server.

```bash
# copy a database                          # on the receiving host
pg_dump mydb | bandrop pipe --to hostB     bandrop pipe --listen > mydb.sql

# stream a folder as a tarball
tar c ./project | bandrop pipe --to hostB  bandrop pipe --listen | tar x

# clone a disk, watch a log, move anything a pipe can carry
```

The connecting side prints the code (on stderr); the listening side reads it
from the terminal, so piped data never collides with the prompt. `--code`
passes it non-interactively.

### Serve to a browser (+ QR)

```bash
bandrop serve slides.pdf video.mp4 --once
```

Prints a LAN URL and a scannable QR code. Open it on a phone or any device —
it downloads in the browser, no Bandrop needed on the other side. This mode is
plain HTTP for convenience; use it on networks you trust.

### Broadcast to many at once

```bash
bandrop broadcast slides.pdf          # one code, shown once
# on each device:
bandrop receive --broadcast           # discovers the broadcaster, then enter the code
```

Every receiver gets its own end-to-end-encrypted copy; still no server in the
middle.

### Signed receipts

Every `send` signs a receipt with your Ed25519 identity: timestamp, your public
key, and each file's SHA-256. `receive --receipt out.json` saves it, and anyone
can check it later:

```bash
bandrop verify out.json      # VALID receipt, signed by 9cf8:2f8b:… + file list
```

Alter any recorded file, size, or hash and verification fails.

## Security model

- **Pairing:** SPAKE2 (RFC 9382, P-256). The code never crosses the wire and an
  attacker gets only one online guess per connection — no offline brute force.
- **In transit:** AES-256-GCM authenticated encryption, fresh nonce per frame;
  tampering and truncation are detected.
- **Integrity:** per-file SHA-256, end to end.
- **Identity/receipts:** Ed25519 signatures.

`serve` is the one exception: plain HTTP on the LAN, by design, so any browser
can use it. Everything else is end-to-end encrypted and direct — there is no
relay or cloud component anywhere.

Bandrop is a compact tool with a clear threat model (a trusted local network);
it is not an audited replacement for a hardened transport on a hostile network.

## Building & testing

```bash
make            # build
make test       # unit tests (crypto, SPAKE2, QR, JSON, receipts)
bash tests/e2e.sh build/bandrop        # end-to-end file transfer
bash tests/pipe_e2e.sh build/bandrop   # pipe
bash tests/serve_e2e.sh build/bandrop  # browser serve
bash tests/receipt_e2e.sh build/bandrop
```

CI builds and runs all of this on Linux and macOS.

## Module layout

| File | Responsibility |
|------|----------------|
| `crypto.h` | AES-256-GCM, HKDF, HMAC, SHA-256, RNG |
| `spake2.h` / `handshake.h` | SPAKE2 PAKE and the pairing exchange |
| `session.h` | Sealed, length-framed message channel |
| `protocol.h` | Framing, serialization, path hygiene |
| `net.h` / `discovery.h` | TCP helpers and UDP peer discovery |
| `archive.h` / `compress.h` | Directory walking, optional zlib |
| `sender.h` / `receiver.h` / `pipe.h` / `serve.h` | The transfer modes |
| `qr.h` | Self-contained QR encoder (verified against a reference) |
| `identity.h` / `receipt.h` / `json.h` | Ed25519 identity & signed receipts |
| `ui.h` | Progress bar, rate/ETA, human sizes |

---
*Built with ❤️ by Ilia Banda. MIT licensed.*
