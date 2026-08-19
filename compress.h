#pragma once
#include <zlib.h>
#include <cstdint>
#include <stdexcept>
#include <vector>

// Optional zlib compression for file data. Each compressed chunk is framed as
// a 4-byte big-endian raw length followed by the deflated bytes, so the
// receiver can size its inflate buffer exactly.
namespace zip {

inline std::vector<unsigned char> deflate(const unsigned char* data, size_t len) {
    uLongf bound = compressBound((uLong)len);
    std::vector<unsigned char> out(4 + bound);
    out[0] = (unsigned char)(len >> 24); out[1] = (unsigned char)(len >> 16);
    out[2] = (unsigned char)(len >> 8);  out[3] = (unsigned char)(len);
    uLongf dlen = bound;
    if (compress2(out.data() + 4, &dlen, data, (uLong)len, Z_BEST_SPEED) != Z_OK)
        throw std::runtime_error("deflate failed");
    out.resize(4 + dlen);
    return out;
}

// Inflate a framed chunk. Returns the raw bytes, or throws on corruption.
inline std::vector<unsigned char> inflate(const unsigned char* in, size_t len) {
    if (len < 4) throw std::runtime_error("short compressed chunk");
    uLongf raw = ((uLongf)in[0] << 24) | ((uLongf)in[1] << 16) |
                 ((uLongf)in[2] << 8) | (uLongf)in[3];
    std::vector<unsigned char> out(raw);
    uLongf outlen = raw;
    if (uncompress(out.data(), &outlen, in + 4, (uLong)(len - 4)) != Z_OK || outlen != raw)
        throw std::runtime_error("inflate failed");
    return out;
}

} // namespace zip
