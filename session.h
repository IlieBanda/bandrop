#pragma once
#include <vector>
#include "crypto.h"
#include "protocol.h"

// An authenticated session over a connected socket. After the SPAKE2 handshake
// establishes a shared key, all messages are GCM-sealed and length-framed.
class Session {
public:
    Session(int fd, std::vector<unsigned char> key) : fd_(fd), key_(std::move(key)) {}

    // Seal and send one typed message.
    bool send(uint8_t type, const std::vector<unsigned char>& payload) {
        std::vector<unsigned char> pt;
        pt.reserve(1 + payload.size());
        pt.push_back(type);
        pt.insert(pt.end(), payload.begin(), payload.end());
        std::vector<unsigned char> out(crypto::NONCE_LEN + pt.size() + crypto::TAG_LEN);
        int n = crypto::seal(key_.data(), pt.data(), (int)pt.size(), nullptr, 0, out.data());
        if (n < 0) return false;
        return proto::send_frame(fd_, out.data(), (uint32_t)n);
    }

    // Receive one typed message. Returns 1 on success, 0 on clean EOF, -1 on
    // error (including authentication failure — i.e. tampering).
    int recv(uint8_t& type, std::vector<unsigned char>& payload) {
        uint32_t len = 0;
        int r = proto::recv_frame(fd_, frame_, &len);
        if (r <= 0) return r;
        if (plain_.size() < len) plain_.resize(len);
        int n = crypto::open(key_.data(), frame_.data(), (int)len, nullptr, 0, plain_.data());
        if (n < 1) return -1;
        type = plain_[0];
        payload.assign(plain_.begin() + 1, plain_.begin() + n);
        return 1;
    }

private:
    int fd_;
    std::vector<unsigned char> key_;
    std::vector<unsigned char> frame_;
    std::vector<unsigned char> plain_;
};
