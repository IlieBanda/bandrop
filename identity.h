#pragma once
#include <openssl/evp.h>
#include <sys/stat.h>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>
#include "crypto.h"

// A persistent Ed25519 identity for signing transfer receipts. The private key
// lives at $XDG_CONFIG_HOME/bandrop/identity.key (or ~/.config/bandrop/), is
// created on first use, and the corresponding public key acts as the sender's
// verifiable identity (like an SSH or minisign key).
namespace identity {

inline std::string config_dir() {
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    std::string base = (xdg && *xdg) ? xdg : (std::string(std::getenv("HOME") ? std::getenv("HOME") : ".") + "/.config");
    return base + "/bandrop";
}

// Raw 32-byte Ed25519 private + public key material.
struct Key {
    std::vector<unsigned char> priv;  // 32 bytes (seed)
    std::vector<unsigned char> pub;   // 32 bytes
};

inline std::vector<unsigned char> pub_from_priv(const std::vector<unsigned char>& priv) {
    EVP_PKEY* pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, priv.data(), priv.size());
    std::vector<unsigned char> pub(32);
    size_t len = pub.size();
    EVP_PKEY_get_raw_public_key(pk, pub.data(), &len);
    pub.resize(len);
    EVP_PKEY_free(pk);
    return pub;
}

// Load the identity, generating and persisting one on first use.
inline Key load_or_create() {
    std::string dir = config_dir();
    std::string path = dir + "/identity.key";
    std::ifstream in(path, std::ios::binary);
    if (in) {
        std::vector<unsigned char> priv((std::istreambuf_iterator<char>(in)), {});
        if (priv.size() == 32) return {priv, pub_from_priv(priv)};
    }
    // Generate a new key.
    EVP_PKEY* pk = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pk);
    EVP_PKEY_CTX_free(ctx);
    std::vector<unsigned char> priv(32); size_t l = priv.size();
    EVP_PKEY_get_raw_private_key(pk, priv.data(), &l); priv.resize(l);
    std::vector<unsigned char> pub = pub_from_priv(priv);
    EVP_PKEY_free(pk);
    ::mkdir(config_dir().c_str(), 0700);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write((const char*)priv.data(), priv.size());
    out.close();
    ::chmod(path.c_str(), 0600);
    return {priv, pub};
}

inline std::vector<unsigned char> sign(const Key& k, const unsigned char* msg, size_t len) {
    EVP_PKEY* pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, k.priv.data(), k.priv.size());
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestSignInit(md, nullptr, nullptr, nullptr, pk);
    size_t siglen = 0;
    EVP_DigestSign(md, nullptr, &siglen, msg, len);
    std::vector<unsigned char> sig(siglen);
    EVP_DigestSign(md, sig.data(), &siglen, msg, len);
    sig.resize(siglen);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(pk);
    return sig;
}

inline bool verify(const std::vector<unsigned char>& pub, const unsigned char* msg, size_t len,
                   const std::vector<unsigned char>& sig) {
    EVP_PKEY* pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
    if (!pk) return false;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(md, nullptr, nullptr, nullptr, pk);
    bool ok = EVP_DigestVerify(md, sig.data(), sig.size(), msg, len) == 1;
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(pk);
    return ok;
}

// Short hex fingerprint of a public key (first 8 bytes).
inline std::string fingerprint(const std::vector<unsigned char>& pub) {
    static const char* h = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 8 && i < (int)pub.size(); ++i) {
        s += h[pub[i] >> 4]; s += h[pub[i] & 15];
        if (i % 2 == 1 && i != 7) s += ':';
    }
    return s;
}

} // namespace identity
