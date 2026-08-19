#pragma once
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

// Wire framing, serialization helpers and the transfer message format.
//
// After the SPAKE2 handshake, every application message is GCM-sealed and sent
// as a length-prefixed frame. Each plaintext message starts with a one-byte
// type tag followed by a serialized payload.
namespace proto {

constexpr uint32_t MAX_FRAME = 4u << 20;   // 4 MiB hard cap on any frame
constexpr int CHUNK_SIZE = 128 * 1024;     // plaintext file chunk size
constexpr uint16_t PROTOCOL_VERSION = 2;

// Message types inside the encrypted stream.
enum MsgType : uint8_t {
    MSG_MANIFEST   = 1,  // whole-transfer summary
    MSG_FILE_START = 2,  // begin a file: relpath + size
    MSG_DATA       = 3,  // a chunk of the current file
    MSG_FILE_END   = 4,  // end a file: sha256 of its contents
    MSG_DONE       = 5,  // transfer complete
};

// --- reliable stream I/O -------------------------------------------------

inline bool send_all(int fd, const void* buf, size_t len) {
    const char* p = static_cast<const char*>(buf);
    while (len > 0) {
        ssize_t n = ::send(fd, p, len, 0);
        if (n <= 0) return false;
        p += n; len -= static_cast<size_t>(n);
    }
    return true;
}

inline bool recv_all(int fd, void* buf, size_t len) {
    char* p = static_cast<char*>(buf);
    while (len > 0) {
        ssize_t n = ::recv(fd, p, len, 0);
        if (n <= 0) return false;
        p += n; len -= static_cast<size_t>(n);
    }
    return true;
}

// --- length-framed messages (4-byte big-endian prefix) -------------------

inline bool send_frame(int fd, const unsigned char* payload, uint32_t len) {
    unsigned char hdr[4] = {
        (unsigned char)(len >> 24), (unsigned char)(len >> 16),
        (unsigned char)(len >> 8),  (unsigned char)(len)};
    return send_all(fd, hdr, 4) && send_all(fd, payload, len);
}

// Returns 1 on success (fills buf/out_len), 0 on clean EOF, -1 on error.
inline int recv_frame(int fd, std::vector<unsigned char>& buf, uint32_t* out_len) {
    unsigned char hdr[4];
    ssize_t n = ::recv(fd, hdr, 4, MSG_WAITALL);
    if (n == 0) return 0;
    if (n != 4) return -1;
    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
    if (len == 0 || len > MAX_FRAME) return -1;
    if (buf.size() < len) buf.resize(len);
    if (!recv_all(fd, buf.data(), len)) return -1;
    *out_len = len;
    return 1;
}

// --- little serialization helpers ---------------------------------------

struct Writer {
    std::vector<unsigned char> buf;
    void u8(uint8_t v) { buf.push_back(v); }
    void u16(uint16_t v) { for (int i = 1; i >= 0; --i) buf.push_back((v >> (8 * i)) & 0xff); }
    void u32(uint32_t v) { for (int i = 3; i >= 0; --i) buf.push_back((v >> (8 * i)) & 0xff); }
    void u64(uint64_t v) { for (int i = 7; i >= 0; --i) buf.push_back((v >> (8 * i)) & 0xff); }
    void bytes(const unsigned char* p, size_t n) { buf.insert(buf.end(), p, p + n); }
    void str(const std::string& s) { u32((uint32_t)s.size()); buf.insert(buf.end(), s.begin(), s.end()); }
    void blob(const std::vector<unsigned char>& v) { u32((uint32_t)v.size()); bytes(v.data(), v.size()); }
};

struct Reader {
    const unsigned char* p;
    size_t left;
    bool ok = true;
    Reader(const unsigned char* d, size_t n) : p(d), left(n) {}
    uint8_t u8() { if (left < 1) { ok = false; return 0; } left--; return *p++; }
    uint16_t u16() { uint16_t v = 0; for (int i = 0; i < 2; ++i) v = (v << 8) | u8(); return v; }
    uint32_t u32() { uint32_t v = 0; for (int i = 0; i < 4; ++i) v = (v << 8) | u8(); return v; }
    uint64_t u64() { uint64_t v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | u8(); return v; }
    std::string str() {
        uint32_t n = u32();
        if (!ok || n > left) { ok = false; return {}; }
        std::string s((const char*)p, n); p += n; left -= n; return s;
    }
    std::vector<unsigned char> blob() {
        uint32_t n = u32();
        if (!ok || n > left) { ok = false; return {}; }
        std::vector<unsigned char> v(p, p + n); p += n; left -= n; return v;
    }
};

// --- path hygiene --------------------------------------------------------

// Reduce an arbitrary name to a safe basename (no directory, no traversal).
inline std::string safe_basename(const std::string& name) {
    std::string base = name;
    size_t slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base = base.substr(slash + 1);
    if (base.empty() || base == "." || base == "..") return "received_file";
    return base;
}

// Sanitize a relative path from an untrusted sender: forbid absolute paths,
// "..", empty, and backslashes; collapse to a safe relative path.
inline std::string safe_relpath(const std::string& raw) {
    if (raw.empty() || raw.front() == '/' || raw.find('\\') != std::string::npos)
        return safe_basename(raw);
    std::string out;
    size_t i = 0;
    while (i < raw.size()) {
        size_t j = raw.find('/', i);
        std::string seg = raw.substr(i, j == std::string::npos ? std::string::npos : j - i);
        if (seg == ".." ) return safe_basename(raw);  // reject traversal outright
        if (!seg.empty() && seg != ".") {
            if (!out.empty()) out += '/';
            out += seg;
        }
        if (j == std::string::npos) break;
        i = j + 1;
    }
    return out.empty() ? "received_file" : out;
}

} // namespace proto
