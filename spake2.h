#pragma once
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <stdexcept>
#include <string>
#include <vector>
#include "crypto.h"

// SPAKE2 password-authenticated key exchange over NIST P-256 (RFC 9382).
//
// Both peers derive the same scalar w from the shared 6-digit PIN and a random
// per-session salt. Each sends a blinded public element; neither the PIN nor
// the derived key ever crosses the wire, and — unlike a plain key-agreement +
// MAC — an eavesdropper or MITM gets no transcript they can brute-force the PIN
// against offline. A wrong PIN simply makes the key-confirmation MACs disagree,
// so the transfer aborts before any file data is exchanged.
//
// Roles: the sender is party A (uses point M), the receiver is party B (N).
class Spake2 {
public:
    enum class Role { A, B };

    Spake2(Role role, const std::string& password, const unsigned char* salt, size_t salt_len)
        : role_(role) {
        group_ = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        ctx_ = BN_CTX_new();
        order_ = BN_new();
        if (!group_ || !ctx_ || !order_) throw std::runtime_error("EC init failed");
        EC_GROUP_get_order(group_, order_, ctx_);

        M_ = point_from_hex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f");
        N_ = point_from_hex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49");

        // w = PBKDF2(PIN, salt) reduced mod group order (extra bytes reduce bias).
        std::vector<unsigned char> wbytes(48);
        if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(), salt, (int)salt_len,
                              200000, EVP_sha256(), (int)wbytes.size(), wbytes.data()) != 1)
            throw std::runtime_error("PBKDF2 failed");
        w_ = BN_new();
        BN_bin2bn(wbytes.data(), (int)wbytes.size(), w_);
        BN_mod(w_, w_, order_, ctx_);

        // Ephemeral secret scalar x (or y).
        secret_ = BN_new();
        BN_rand_range(secret_, order_);

        // Public element: A sends X = x*G + w*M ; B sends Y = y*G + w*N.
        share_ = EC_POINT_new(group_);
        const EC_POINT* blind = (role_ == Role::A) ? M_ : N_;
        EC_POINT_mul(group_, share_, secret_, blind, w_, ctx_);
    }

    ~Spake2() {
        if (M_) EC_POINT_free(M_);
        if (N_) EC_POINT_free(N_);
        if (share_) EC_POINT_free(share_);
        if (w_) BN_free(w_);
        if (secret_) BN_free(secret_);
        if (order_) BN_free(order_);
        if (ctx_) BN_CTX_free(ctx_);
        if (group_) EC_GROUP_free(group_);
    }

    // Our public element, as a 33-byte compressed point, to send to the peer.
    std::vector<unsigned char> public_share() const { return point_to_bytes(share_); }

    // Result of completing the handshake with the peer's public element.
    struct Session {
        std::vector<unsigned char> key;     // 32-byte AES session key
        std::vector<unsigned char> confirm; // MAC we send to the peer
    };

    // Consume the peer's public element and derive the shared session key plus
    // our key-confirmation MAC. `peer` must be a 33-byte compressed point.
    Session finish(const std::vector<unsigned char>& peer) {
        EC_POINT* P = point_from_bytes(peer);
        if (!P) throw std::runtime_error("bad peer element");

        // Recover the shared point K.
        //   A: K = x * (Y - w*N)      B: K = y * (X - w*M)
        const EC_POINT* their_blind = (role_ == Role::A) ? N_ : M_;
        EC_POINT* wB = EC_POINT_new(group_);
        EC_POINT_mul(group_, wB, nullptr, their_blind, w_, ctx_); // w*(N or M)
        EC_POINT_invert(group_, wB, ctx_);                        // -w*(N or M)
        EC_POINT* T = EC_POINT_new(group_);
        EC_POINT_add(group_, T, P, wB, ctx_);                     // peer - w*blind
        EC_POINT* K = EC_POINT_new(group_);
        EC_POINT_mul(group_, K, nullptr, T, secret_, ctx_);       // secret * T

        std::vector<unsigned char> kbytes = point_to_bytes(K);
        std::vector<unsigned char> xb = point_to_bytes(share_);
        std::vector<unsigned char> yb = peer;

        EC_POINT_free(P);
        EC_POINT_free(wB);
        EC_POINT_free(T);
        EC_POINT_free(K);

        // Transcript binds both public elements and the shared secret. A and B
        // must build it identically, so order by role, not by "us/them".
        const std::vector<unsigned char>& Xb = (role_ == Role::A) ? xb : yb;
        const std::vector<unsigned char>& Yb = (role_ == Role::A) ? yb : xb;
        std::vector<unsigned char> tt;
        auto app = [&](const std::vector<unsigned char>& v) { tt.insert(tt.end(), v.begin(), v.end()); };
        app(Xb); app(Yb); app(kbytes);
        std::vector<unsigned char> tt_hash = crypto::sha256(tt.data(), tt.size());

        // Derive session key + two confirmation keys.
        std::vector<unsigned char> okm =
            crypto::hkdf(kbytes.data(), kbytes.size(), tt_hash.data(), tt_hash.size(),
                         "bandrop-spake2-v1", 96);
        std::vector<unsigned char> ke(okm.begin(), okm.begin() + 32);
        std::vector<unsigned char> kcA(okm.begin() + 32, okm.begin() + 64);
        std::vector<unsigned char> kcB(okm.begin() + 64, okm.begin() + 96);

        // Each side confirms by MAC'ing the *other* party's element.
        my_confirm_key_    = (role_ == Role::A) ? kcA : kcB;
        peer_confirm_key_  = (role_ == Role::A) ? kcB : kcA;
        peer_element_      = (role_ == Role::A) ? Yb : Xb;   // peer's own element
        my_element_        = (role_ == Role::A) ? Xb : Yb;

        Session s;
        s.key = ke;
        s.confirm = crypto::hmac_sha256(my_confirm_key_.data(), my_confirm_key_.size(),
                                        peer_element_.data(), peer_element_.size());
        return s;
    }

    // Verify the peer's confirmation MAC (constant-time compare).
    bool verify_peer(const std::vector<unsigned char>& mac) const {
        std::vector<unsigned char> expect =
            crypto::hmac_sha256(peer_confirm_key_.data(), peer_confirm_key_.size(),
                                my_element_.data(), my_element_.size());
        if (mac.size() != expect.size()) return false;
        return CRYPTO_memcmp(mac.data(), expect.data(), expect.size()) == 0;
    }

private:
    EC_POINT* point_from_hex(const char* hex) {
        BIGNUM* bn = nullptr;
        BN_hex2bn(&bn, hex);
        int len = BN_num_bytes(bn);
        std::vector<unsigned char> buf(len);
        BN_bn2bin(bn, buf.data());
        BN_free(bn);
        EC_POINT* p = EC_POINT_new(group_);
        if (EC_POINT_oct2point(group_, p, buf.data(), buf.size(), ctx_) != 1) {
            EC_POINT_free(p);
            throw std::runtime_error("bad fixed point");
        }
        return p;
    }

    EC_POINT* point_from_bytes(const std::vector<unsigned char>& b) const {
        EC_POINT* p = EC_POINT_new(group_);
        if (EC_POINT_oct2point(group_, p, b.data(), b.size(), ctx_) != 1) {
            EC_POINT_free(p);
            return nullptr;
        }
        return p;
    }

    std::vector<unsigned char> point_to_bytes(const EC_POINT* p) const {
        size_t n = EC_POINT_point2oct(group_, p, POINT_CONVERSION_COMPRESSED,
                                      nullptr, 0, ctx_);
        std::vector<unsigned char> out(n);
        EC_POINT_point2oct(group_, p, POINT_CONVERSION_COMPRESSED, out.data(), n, ctx_);
        return out;
    }

    Role role_;
    EC_GROUP* group_ = nullptr;
    BN_CTX* ctx_ = nullptr;
    BIGNUM* order_ = nullptr;
    BIGNUM* w_ = nullptr;
    BIGNUM* secret_ = nullptr;
    EC_POINT* M_ = nullptr;
    EC_POINT* N_ = nullptr;
    EC_POINT* share_ = nullptr;
    std::vector<unsigned char> my_confirm_key_, peer_confirm_key_;
    std::vector<unsigned char> my_element_, peer_element_;
};
