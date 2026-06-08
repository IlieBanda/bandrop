# 🚀 Bandrop

**Bandrop** is a blazingly fast, secure, and lightweight P2P (Peer-to-Peer) file transfer CLI utility written in pure C++.

Inspired by *Magic Wormhole* and *AirDrop*, Bandrop allows you to securely send files across your local network using a simple 6-digit pairing code. No cloud servers, no file size limits, no tracking.

## ✨ Features
- **End-to-End Encryption:** Your files are encrypted on the fly using military-grade **AES-256-CBC**.
- **Password Pairing:** No need to share long encryption keys. Bandrop generates a random 6-digit PIN and securely hashes it using **SHA-256** to derive the AES key.
- **Console UI:** Includes a beautiful terminal progress bar and automatic original file name preservation.
- **Zero Dependencies:** Written in raw C++ POSIX sockets. Only requires OpenSSL.

## 🛠️ Build & Install

```bash
git clone https://github.com/IlieBanda/bandrop.git
cd bandrop
mkdir build && cd build
cmake ..
make
```

## 📖 Usage

### Receiver (Server)
Start listening for incoming files. It will prompt you for the 6-digit pairing code provided by the sender.
```bash
./bandrop receive
# Or specify a custom port:
./bandrop receive --port 8080
```

### Sender (Client)
Send a file using the interactive mode or the single-line command:
```bash
./bandrop send <ip_address> /path/to/file.mp4
```
Bandrop will output a 6-digit connection code. Share this code with the receiver to securely transmit the file!

---
*Built with ❤️ by Ilia Banda*
