#pragma once
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

// Cryptographic primitives for Bandrop.
//
// Transport confidentiality/integrity uses AES-256-GCM (AEAD): every wire
// message carries a fresh 96-bit nonce and a 128-bit authentication tag, so
// tampering or truncation is detected on decryption. Session keys come from
// the SPAKE2 handshake (see spake2.h); this file provides the AEAD, HKDF,
// HMAC and streaming SHA-256 helpers it and the transfer code rely on.
namespace crypto {

constexpr int KEY_LEN = 32;   // AES-256
constexpr int NONCE_LEN = 12; // GCM nonce
constexpr int TAG_LEN = 16;   // GCM tag
constexpr int SALT_LEN = 16;

inline bool random_bytes(unsigned char* buf, int len) {
    return RAND_bytes(buf, len) == 1;
}

inline std::vector<unsigned char> random_vec(int len) {
    std::vector<unsigned char> v(len);
    if (!random_bytes(v.data(), len)) throw std::runtime_error("RAND_bytes failed");
    return v;
}

// --- SHA-256 -------------------------------------------------------------

inline std::vector<unsigned char> sha256(const unsigned char* data, size_t len) {
    std::vector<unsigned char> out(SHA256_DIGEST_LENGTH);
    SHA256(data, len, out.data());
    return out;
}

// Incremental SHA-256 for hashing a file as it streams by.
class Sha256 {
public:
    Sha256() : ctx_(EVP_MD_CTX_new()) { EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr); }
    ~Sha256() { if (ctx_) EVP_MD_CTX_free(ctx_); }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    void update(const unsigned char* d, size_t n) { EVP_DigestUpdate(ctx_, d, n); }
    std::vector<unsigned char> final() {
        std::vector<unsigned char> out(SHA256_DIGEST_LENGTH);
        unsigned int len = 0;
        EVP_DigestFinal_ex(ctx_, out.data(), &len);
        out.resize(len);
        return out;
    }
private:
    EVP_MD_CTX* ctx_;
};

// --- HMAC-SHA256 & HKDF --------------------------------------------------

inline std::vector<unsigned char> hmac_sha256(const unsigned char* key, size_t key_len,
                                              const unsigned char* data, size_t data_len) {
    std::vector<unsigned char> out(SHA256_DIGEST_LENGTH);
    unsigned int outlen = 0;
    HMAC(EVP_sha256(), key, static_cast<int>(key_len), data, data_len, out.data(), &outlen);
    out.resize(outlen);
    return out;
}

// HKDF (RFC 5869) extract-then-expand, producing `length` bytes.
inline std::vector<unsigned char> hkdf(const unsigned char* ikm, size_t ikm_len,
                                       const unsigned char* salt, size_t salt_len,
                                       const std::string& info, size_t length) {
    std::vector<unsigned char> prk = hmac_sha256(salt, salt_len, ikm, ikm_len);
    std::vector<unsigned char> okm;
    std::vector<unsigned char> t;
    unsigned char counter = 1;
    while (okm.size() < length) {
        std::vector<unsigned char> input = t;
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter++);
        t = hmac_sha256(prk.data(), prk.size(), input.data(), input.size());
        okm.insert(okm.end(), t.begin(), t.end());
    }
    okm.resize(length);
    return okm;
}

// --- AES-256-GCM AEAD ----------------------------------------------------

// Seal `pt_len` plaintext bytes under `key` (32 bytes) with optional
// associated data. Writes nonce || ciphertext || tag into `out` (which needs
// NONCE_LEN + pt_len + TAG_LEN bytes). Returns bytes written or -1.
inline int seal(const unsigned char* key,
                const unsigned char* pt, int pt_len,
                const unsigned char* aad, int aad_len,
                unsigned char* out) {
    unsigned char* nonce = out;
    if (!random_bytes(nonce, NONCE_LEN)) return -1;
    unsigned char* ct = out + NONCE_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int result = -1, len = 0, total = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1) {
        int tmp = 0;
        bool ok = true;
        if (aad && aad_len > 0)
            ok = EVP_EncryptUpdate(ctx, nullptr, &tmp, aad, aad_len) == 1;
        if (ok && EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) == 1) {
            total = len;
            if (EVP_EncryptFinal_ex(ctx, ct + total, &len) == 1) {
                total += len;
                unsigned char* tag = ct + total;
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) == 1)
                    result = NONCE_LEN + total + TAG_LEN;
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

// Open a sealed message (nonce || ciphertext || tag). Returns plaintext length
// or -1 on authentication failure (wrong key, tampering, truncation).
inline int open(const unsigned char* key,
                const unsigned char* in, int in_len,
                const unsigned char* aad, int aad_len,
                unsigned char* out) {
    if (in_len < NONCE_LEN + TAG_LEN) return -1;
    const unsigned char* nonce = in;
    const unsigned char* ct = in + NONCE_LEN;
    int ct_len = in_len - NONCE_LEN - TAG_LEN;
    const unsigned char* tag = in + in_len - TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int result = -1, len = 0, total = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1) {
        int tmp = 0;
        bool ok = true;
        if (aad && aad_len > 0)
            ok = EVP_DecryptUpdate(ctx, nullptr, &tmp, aad, aad_len) == 1;
        if (ok && EVP_DecryptUpdate(ctx, out, &len, ct, ct_len) == 1) {
            total = len;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                                    const_cast<unsigned char*>(tag)) == 1 &&
                EVP_DecryptFinal_ex(ctx, out + total, &len) == 1) {
                total += len;
                result = total;
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

} // namespace crypto
