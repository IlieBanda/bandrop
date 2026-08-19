#pragma once
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <vector>
#include "protocol.h"

// Zero-config discovery over UDP broadcast. A waiting receiver answers
// discovery queries with its TCP port and a friendly name, so a sender can
// find peers on the LAN without anyone typing an IP address.
namespace discovery {

constexpr int DISCOVERY_PORT = 47474;
static const char QUERY_MAGIC[6]  = {'B','N','D','R','P','?'};
static const char REPLY_MAGIC[6]  = {'B','N','D','R','P','!'};

struct Peer {
    std::string ip;
    int port;
    std::string name;
    int service = 0;   // 0 = receiver (1:1), 1 = broadcaster
};

// Open a UDP socket bound to the discovery port to answer queries.
inline int open_responder() {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(DISCOVERY_PORT);
    if (::bind(fd, (sockaddr*)&a, sizeof(a)) < 0) { ::close(fd); return -1; }
    return fd;
}

// Answer one pending query on `fd`, advertising `tcp_port` and `name`.
inline void answer_query(int fd, int tcp_port, const std::string& name, int service = 0) {
    unsigned char buf[512];
    sockaddr_in from{}; socklen_t fl = sizeof(from);
    ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
    if (n < (ssize_t)sizeof(QUERY_MAGIC)) return;
    if (std::memcmp(buf, QUERY_MAGIC, sizeof(QUERY_MAGIC)) != 0) return;
    proto::Writer w;
    w.bytes((const unsigned char*)REPLY_MAGIC, sizeof(REPLY_MAGIC));
    w.u16(proto::PROTOCOL_VERSION);
    w.u16((uint16_t)tcp_port);
    w.str(name);
    w.u8((uint8_t)service);
    ::sendto(fd, w.buf.data(), w.buf.size(), 0, (sockaddr*)&from, fl);
}

// Broadcast a discovery query and collect replies for `timeout_ms`.
inline std::vector<Peer> browse(int timeout_ms = 1200) {
    std::vector<Peer> peers;
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return peers;
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));

    sockaddr_in bcast{};
    bcast.sin_family = AF_INET;
    bcast.sin_port = htons(DISCOVERY_PORT);
    bcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    ::sendto(fd, QUERY_MAGIC, sizeof(QUERY_MAGIC), 0, (sockaddr*)&bcast, sizeof(bcast));
    // Also hit loopback so same-host discovery works for testing/local use.
    sockaddr_in lo = bcast;
    inet_pton(AF_INET, "127.0.0.1", &lo.sin_addr);
    ::sendto(fd, QUERY_MAGIC, sizeof(QUERY_MAGIC), 0, (sockaddr*)&lo, sizeof(lo));

    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (;;) {
        unsigned char buf[512];
        sockaddr_in from{}; socklen_t fl = sizeof(from);
        ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
        if (n <= 0) break;
        if (n < (ssize_t)(sizeof(REPLY_MAGIC) + 4)) continue;
        if (std::memcmp(buf, REPLY_MAGIC, sizeof(REPLY_MAGIC)) != 0) continue;
        proto::Reader r(buf + sizeof(REPLY_MAGIC), n - sizeof(REPLY_MAGIC));
        r.u16(); // version
        int port = r.u16();
        std::string name = r.str();
        if (!r.ok) continue;
        int service = 0;
        if (r.left >= 1) service = r.u8();
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        bool dup = false;
        for (auto& p : peers) if (p.ip == ip && p.port == port) dup = true;
        if (!dup) peers.push_back({ip, port, name, service});
    }
    ::close(fd);
    return peers;
}

} // namespace discovery
