#pragma once
#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include <vector>
#include "crypto.h"
#include "protocol.h"
#include "spake2.h"

// The SPAKE2 pairing handshake, shared by every mode (send/receive/pipe/...).
//
// One peer is the initiator (role A): it generates the session salt and its
// public element, and drives the exchange. The other is the responder (B).
// On success both return the identical 32-byte session key; a wrong code makes
// key confirmation fail and both return an empty optional without exchanging
// any payload.
namespace handshake {

using Key = std::vector<unsigned char>;

// Initiator side. `password` is the full pairing code (known up front).
inline std::optional<Key> initiator(int fd, const std::string& password) {
    auto salt = crypto::random_vec(crypto::SALT_LEN);
    Spake2 spake(Spake2::Role::A, password, salt.data(), salt.size());

    proto::Writer hello;
    hello.u16(proto::PROTOCOL_VERSION);
    hello.bytes(salt.data(), salt.size());
    hello.blob(spake.public_share());
    if (!proto::send_frame(fd, hello.buf.data(), (uint32_t)hello.buf.size())) return std::nullopt;

    std::vector<unsigned char> buf; uint32_t len = 0;
    if (proto::recv_frame(fd, buf, &len) != 1) return std::nullopt;
    proto::Reader rr(buf.data(), len);
    auto peer_share = rr.blob();
    auto peer_confirm = rr.blob();
    if (!rr.ok) return std::nullopt;

    Spake2::Session s = spake.finish(peer_share);
    if (!spake.verify_peer(peer_confirm)) return std::nullopt;

    proto::Writer conf; conf.blob(s.confirm);
    if (!proto::send_frame(fd, conf.buf.data(), (uint32_t)conf.buf.size())) return std::nullopt;
    return s.key;
}

// Responder side. `get_password` is invoked *after* HELLO arrives (so an
// interactive prompt appears at the right moment); return the pairing code.
// `on_version_mismatch` is optional diagnostics.
inline std::optional<Key> responder(
    int fd,
    const std::function<std::string()>& get_password,
    const std::function<void(uint16_t)>& on_version_mismatch = {}) {

    std::vector<unsigned char> buf; uint32_t len = 0;
    if (proto::recv_frame(fd, buf, &len) != 1) return std::nullopt;
    proto::Reader hr(buf.data(), len);
    uint16_t ver = hr.u16();
    if (ver != proto::PROTOCOL_VERSION) {
        if (on_version_mismatch) on_version_mismatch(ver);
        return std::nullopt;
    }
    unsigned char salt[crypto::SALT_LEN];
    for (int i = 0; i < crypto::SALT_LEN; ++i) salt[i] = hr.u8();
    auto peer_share = hr.blob();
    if (!hr.ok) return std::nullopt;

    std::string password = get_password();
    Spake2 spake(Spake2::Role::B, password, salt, sizeof(salt));
    Spake2::Session s = spake.finish(peer_share);

    proto::Writer reply;
    reply.blob(spake.public_share());
    reply.blob(s.confirm);
    if (!proto::send_frame(fd, reply.buf.data(), (uint32_t)reply.buf.size())) return std::nullopt;

    if (proto::recv_frame(fd, buf, &len) != 1) return std::nullopt;
    proto::Reader cr(buf.data(), len);
    auto peer_confirm = cr.blob();
    if (!cr.ok || !spake.verify_peer(peer_confirm)) return std::nullopt;
    return s.key;
}

} // namespace handshake
