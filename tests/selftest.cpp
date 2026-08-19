#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include "../crypto.h"
#include "../spake2.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << msg << "\n"; ++failures; } \
                              else { std::cout << "ok: " << msg << "\n"; } } while (0)

static void test_gcm_roundtrip() {
    auto key = crypto::random_vec(crypto::KEY_LEN);
    const char* msg = "hello bandrop, this is a secret payload";
    int pl = (int)std::strlen(msg);
    std::vector<unsigned char> out(crypto::NONCE_LEN + pl + crypto::TAG_LEN);
    int n = crypto::seal(key.data(), (const unsigned char*)msg, pl, nullptr, 0, out.data());
    CHECK(n > 0, "gcm seal");
    std::vector<unsigned char> dec(pl + 16);
    int d = crypto::open(key.data(), out.data(), n, nullptr, 0, dec.data());
    CHECK(d == pl && std::memcmp(dec.data(), msg, pl) == 0, "gcm open roundtrip");
}

static void test_gcm_tamper() {
    auto key = crypto::random_vec(crypto::KEY_LEN);
    const char* msg = "tamper me";
    int pl = (int)std::strlen(msg);
    std::vector<unsigned char> out(crypto::NONCE_LEN + pl + crypto::TAG_LEN);
    int n = crypto::seal(key.data(), (const unsigned char*)msg, pl, nullptr, 0, out.data());
    out[crypto::NONCE_LEN + 2] ^= 0x40; // flip a ciphertext bit
    std::vector<unsigned char> dec(pl + 16);
    int d = crypto::open(key.data(), out.data(), n, nullptr, 0, dec.data());
    CHECK(d == -1, "gcm rejects tampered ciphertext");
}

static void test_gcm_wrong_key() {
    auto key = crypto::random_vec(crypto::KEY_LEN);
    auto bad = crypto::random_vec(crypto::KEY_LEN);
    const char* msg = "x";
    std::vector<unsigned char> out(crypto::NONCE_LEN + 1 + crypto::TAG_LEN);
    int n = crypto::seal(key.data(), (const unsigned char*)msg, 1, nullptr, 0, out.data());
    std::vector<unsigned char> dec(32);
    CHECK(crypto::open(bad.data(), out.data(), n, nullptr, 0, dec.data()) == -1,
          "gcm rejects wrong key");
}

static void test_hkdf_deterministic() {
    unsigned char ikm[8] = {1,2,3,4,5,6,7,8};
    unsigned char salt[4] = {9,9,9,9};
    auto a = crypto::hkdf(ikm, 8, salt, 4, "info", 40);
    auto b = crypto::hkdf(ikm, 8, salt, 4, "info", 40);
    auto c = crypto::hkdf(ikm, 8, salt, 4, "other", 40);
    CHECK(a == b && a.size() == 40, "hkdf deterministic, right length");
    CHECK(a != c, "hkdf differs by info");
}

static void test_spake2_agreement() {
    auto salt = crypto::random_vec(crypto::SALT_LEN);
    Spake2 a(Spake2::Role::A, "473829", salt.data(), salt.size());
    Spake2 b(Spake2::Role::B, "473829", salt.data(), salt.size());
    auto sa = a.finish(b.public_share());
    auto sb = b.finish(a.public_share());
    CHECK(sa.key == sb.key && sa.key.size() == 32, "spake2 same session key");
    CHECK(a.verify_peer(sb.confirm), "spake2 A verifies B confirm");
    CHECK(b.verify_peer(sa.confirm), "spake2 B verifies A confirm");
}

static void test_spake2_wrong_pin() {
    auto salt = crypto::random_vec(crypto::SALT_LEN);
    Spake2 a(Spake2::Role::A, "111111", salt.data(), salt.size());
    Spake2 b(Spake2::Role::B, "222222", salt.data(), salt.size());
    auto sa = a.finish(b.public_share());
    auto sb = b.finish(a.public_share());
    CHECK(sa.key != sb.key, "spake2 wrong pin -> different keys");
    CHECK(!a.verify_peer(sb.confirm), "spake2 wrong pin -> A rejects");
    CHECK(!b.verify_peer(sa.confirm), "spake2 wrong pin -> B rejects");
}

int main() {
    test_gcm_roundtrip();
    test_gcm_tamper();
    test_gcm_wrong_key();
    test_hkdf_deterministic();
    test_spake2_agreement();
    test_spake2_wrong_pin();
    std::cout << (failures ? "\nSOME TESTS FAILED\n" : "\nALL TESTS PASSED\n");
    return failures ? 1 : 0;
}
