#pragma once
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>
#include <string>

// AES-256-CBC with a fresh random IV per message. The key is derived from the
// pairing PIN and a per-session salt via PBKDF2-HMAC-SHA256. Each encrypted
// message on the wire is laid out as: IV (16 bytes) || ciphertext.
class AesEncryptor {
public:
    static constexpr int KEY_LEN = 32;
    static constexpr int IV_LEN = 16;
    static constexpr int SALT_LEN = 16;
    static constexpr int PBKDF2_ITERS = 200000;

    // Fill `buf` with `len` cryptographically secure random bytes.
    static bool random_bytes(unsigned char* buf, int len) {
        return RAND_bytes(buf, len) == 1;
    }

    // Derive the AES key from the pairing password and salt.
    AesEncryptor(const std::string& password, const unsigned char* salt) {
        if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                              salt, SALT_LEN, PBKDF2_ITERS, EVP_sha256(),
                              KEY_LEN, key_) != 1) {
            throw std::runtime_error("key derivation failed");
        }
    }

    ~AesEncryptor() { OPENSSL_cleanse(key_, sizeof(key_)); }

    // Encrypt `plaintext_len` bytes. Writes IV || ciphertext into `out`, which
    // must have room for IV_LEN + plaintext_len + block padding. Returns the
    // number of bytes written, or -1 on failure.
    int encrypt(const unsigned char* plaintext, int plaintext_len, unsigned char* out) {
        unsigned char* iv = out;
        if (!random_bytes(iv, IV_LEN)) return -1;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return -1;

        int result = -1;
        unsigned char* ct = out + IV_LEN;
        int len = 0, total = 0;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_, iv) == 1 &&
            EVP_EncryptUpdate(ctx, ct, &len, plaintext, plaintext_len) == 1) {
            total = len;
            if (EVP_EncryptFinal_ex(ctx, ct + total, &len) == 1) {
                total += len;
                result = IV_LEN + total;
            }
        }
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    // Decrypt a wire message (IV || ciphertext) of `in_len` bytes into `out`.
    // Returns the plaintext length, or -1 on failure (including a wrong PIN,
    // which surfaces as a padding-check failure).
    int decrypt(const unsigned char* in, int in_len, unsigned char* out) {
        if (in_len < IV_LEN) return -1;
        const unsigned char* iv = in;
        const unsigned char* ct = in + IV_LEN;
        int ct_len = in_len - IV_LEN;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return -1;

        int result = -1;
        int len = 0, total = 0;
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_, iv) == 1 &&
            EVP_DecryptUpdate(ctx, out, &len, ct, ct_len) == 1) {
            total = len;
            if (EVP_DecryptFinal_ex(ctx, out + total, &len) == 1) {
                total += len;
                result = total;
            }
        }
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

private:
    unsigned char key_[KEY_LEN];
};
