#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "crypto.h"

// Content-defined chunking (a FastCDC-style gear rolling hash). Splitting a
// file on content rather than fixed offsets means an insertion or deletion only
// changes the chunks around it, so delta sync can reuse the rest. Chunks are
// identified by their SHA-256, so matches are collision-safe.
namespace chunker {

struct Chunk { uint64_t offset; uint32_t len; std::vector<unsigned char> sha; };

// Deterministic gear table (a fixed PRNG stream) so both peers cut identically.
inline const uint64_t* gear() {
    static uint64_t g[256];
    static bool init = false;
    if (!init) {
        uint64_t x = 0x2545F4914F6CDD1DULL; // fixed seed
        for (int i = 0; i < 256; ++i) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17; // xorshift64
            g[i] = x;
        }
        init = true;
    }
    return g;
}

constexpr uint32_t MIN_CHUNK = 2 * 1024;
constexpr uint32_t AVG_CHUNK = 8 * 1024;
constexpr uint32_t MAX_CHUNK = 64 * 1024;
constexpr uint64_t MASK = (1ULL << 13) - 1; // ~8 KiB average

// Find the length of the next chunk starting at data[pos..len).
inline uint32_t next_boundary(const unsigned char* data, size_t len) {
    if (len <= MIN_CHUNK) return (uint32_t)len;
    size_t limit = len < MAX_CHUNK ? len : MAX_CHUNK;
    uint64_t fp = 0;
    const uint64_t* g = gear();
    size_t i = 0;
    for (; i < MIN_CHUNK; ++i) fp = (fp << 1) + g[data[i]]; // warm up, no cut
    for (; i < limit; ++i) {
        fp = (fp << 1) + g[data[i]];
        if ((fp & MASK) == 0) return (uint32_t)(i + 1);
    }
    return (uint32_t)limit;
}

// Chunk an in-memory buffer.
inline std::vector<Chunk> split(const unsigned char* data, size_t len) {
    std::vector<Chunk> out;
    size_t pos = 0;
    while (pos < len) {
        uint32_t clen = next_boundary(data + pos, len - pos);
        Chunk c;
        c.offset = pos;
        c.len = clen;
        c.sha = crypto::sha256(data + pos, clen);
        out.push_back(std::move(c));
        pos += clen;
    }
    return out;
}

} // namespace chunker
