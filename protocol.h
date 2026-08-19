#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <unistd.h>

// The header sent (encrypted) as the first message of a transfer.
struct FileHeader {
    char filename[256];
    int64_t filesize;
};

// Upper bound on a single wire frame's payload, to reject malformed input.
constexpr uint32_t MAX_FRAME = 1u << 20;   // 1 MiB
constexpr int CHUNK_SIZE = 64 * 1024;      // plaintext chunk size

// --- reliable stream I/O -------------------------------------------------

// Send exactly `len` bytes, looping over partial writes. Returns false on error.
inline bool send_all(int fd, const void* buf, size_t len) {
    const char* p = static_cast<const char*>(buf);
    while (len > 0) {
        ssize_t n = ::send(fd, p, len, 0);
        if (n <= 0) return false;
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

// Receive exactly `len` bytes. Returns false on error or premature EOF.
inline bool recv_all(int fd, void* buf, size_t len) {
    char* p = static_cast<char*>(buf);
    while (len > 0) {
        ssize_t n = ::recv(fd, p, len, 0);
        if (n <= 0) return false;
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

// --- length-framed messages ---------------------------------------------
// TCP is a byte stream, so encrypted messages are framed with a 4-byte
// big-endian length prefix. This is what keeps decrypt() boundaries aligned.

inline bool send_frame(int fd, const unsigned char* payload, uint32_t len) {
    unsigned char hdr[4] = {
        static_cast<unsigned char>(len >> 24),
        static_cast<unsigned char>(len >> 16),
        static_cast<unsigned char>(len >> 8),
        static_cast<unsigned char>(len),
    };
    return send_all(fd, hdr, 4) && send_all(fd, payload, len);
}

// Receive one frame into `buf` (capacity `cap`). On success sets `out_len`.
// Returns 1 on success, 0 on clean EOF (no more frames), -1 on error.
inline int recv_frame(int fd, unsigned char* buf, size_t cap, uint32_t* out_len) {
    unsigned char hdr[4];
    ssize_t n = ::recv(fd, hdr, 4, MSG_WAITALL);
    if (n == 0) return 0;
    if (n != 4) return -1;
    uint32_t len = (static_cast<uint32_t>(hdr[0]) << 24) |
                   (static_cast<uint32_t>(hdr[1]) << 16) |
                   (static_cast<uint32_t>(hdr[2]) << 8) |
                   static_cast<uint32_t>(hdr[3]);
    if (len == 0 || len > MAX_FRAME || len > cap) return -1;
    if (!recv_all(fd, buf, len)) return -1;
    *out_len = len;
    return 1;
}

// --- filename hygiene ----------------------------------------------------

// Reduce an arbitrary path to a safe basename for writing into the CWD.
// Strips any directory components and rejects traversal / empty names.
inline std::string safe_basename(const std::string& name) {
    std::string base = name;
    size_t slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base = base.substr(slash + 1);
    if (base.empty() || base == "." || base == "..") return "received_file";
    return base;
}
