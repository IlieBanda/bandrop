#pragma once
#include <ctime>
#include <string>
#include <vector>
#include "crypto.h"
#include "identity.h"
#include "json.h"

// A signed, verifiable record of a completed transfer: which files (by SHA-256)
// moved, when, and signed by the sender's Ed25519 identity key. Anyone can
// check it later with `bandrop verify` — the sender's public key is the
// identity, so the receipt is self-certifying (trust-on-first-use style).
namespace receipt {

struct FileRec { std::string path; uint64_t size; std::vector<unsigned char> sha; };
struct Receipt {
    uint64_t timestamp = 0;
    std::vector<unsigned char> sender_pub;   // 32 bytes
    std::vector<FileRec> files;
    std::vector<unsigned char> signature;    // 64 bytes
};

inline std::string to_hex(const std::vector<unsigned char>& v) {
    static const char* h = "0123456789abcdef";
    std::string s; for (unsigned char b : v) { s += h[b >> 4]; s += h[b & 15]; } return s;
}
inline std::vector<unsigned char> from_hex(const std::string& s) {
    auto nib = [](char c)->int {
        if (c>='0'&&c<='9') return c-'0';
        if (c>='a'&&c<='f') return c-'a'+10;
        if (c>='A'&&c<='F') return c-'A'+10;
        return 0;
    };
    std::vector<unsigned char> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2) v.push_back((nib(s[i]) << 4) | nib(s[i+1]));
    return v;
}

// Deterministic byte sequence that gets signed (independent of JSON layout).
inline std::vector<unsigned char> digest_input(const Receipt& r) {
    std::vector<unsigned char> b;
    auto u64 = [&](uint64_t v) { for (int i = 7; i >= 0; --i) b.push_back((v >> (8*i)) & 0xff); };
    b.push_back(1); // schema version
    u64(r.timestamp);
    b.insert(b.end(), r.sender_pub.begin(), r.sender_pub.end());
    u64(r.files.size());
    for (auto& f : r.files) {
        u64(f.path.size());
        b.insert(b.end(), f.path.begin(), f.path.end());
        u64(f.size);
        b.insert(b.end(), f.sha.begin(), f.sha.end());
    }
    return b;
}

inline void sign(Receipt& r, const identity::Key& key) {
    r.sender_pub = key.pub;
    auto in = digest_input(r);
    r.signature = identity::sign(key, in.data(), in.size());
}

inline bool verify(const Receipt& r) {
    if (r.sender_pub.size() != 32 || r.signature.empty()) return false;
    auto in = digest_input(r);
    return identity::verify(r.sender_pub, in.data(), in.size(), r.signature);
}

inline std::string iso8601(uint64_t epoch) {
    std::time_t t = (std::time_t)epoch;
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

inline std::string to_json(const Receipt& r) {
    json::Value o = json::Value::O();
    o.set("bandrop_receipt", json::Value::N(1));
    o.set("timestamp", json::Value::S(iso8601(r.timestamp)));
    o.set("timestamp_epoch", json::Value::N((double)r.timestamp));
    o.set("sender", json::Value::S(to_hex(r.sender_pub)));
    o.set("sender_fingerprint", json::Value::S(identity::fingerprint(r.sender_pub)));
    json::Value arr = json::Value::A();
    for (auto& f : r.files) {
        json::Value fo = json::Value::O();
        fo.set("path", json::Value::S(f.path));
        fo.set("size", json::Value::N((double)f.size));
        fo.set("sha256", json::Value::S(to_hex(f.sha)));
        arr.push(fo);
    }
    o.set("files", arr);
    o.set("signature", json::Value::S(to_hex(r.signature)));
    return json::dump(o);
}

inline bool from_json(const std::string& text, Receipt& r) {
    json::Value o;
    if (!json::parse(text, o) || o.type != json::Value::Obj) return false;
    const json::Value* ts = o.find("timestamp_epoch");
    const json::Value* snd = o.find("sender");
    const json::Value* sig = o.find("signature");
    const json::Value* files = o.find("files");
    if (!snd || !sig || !files || files->type != json::Value::Arr) return false;
    r.timestamp = ts ? (uint64_t)ts->num : 0;
    r.sender_pub = from_hex(snd->str);
    r.signature = from_hex(sig->str);
    for (auto& fv : *files->arr) {
        const json::Value* p = fv.find("path");
        const json::Value* sz = fv.find("size");
        const json::Value* sh = fv.find("sha256");
        if (!p || !sz || !sh) return false;
        r.files.push_back({p->str, (uint64_t)sz->num, from_hex(sh->str)});
    }
    return true;
}

} // namespace receipt
