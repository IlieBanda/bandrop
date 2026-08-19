#pragma once
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <string>

// Small TCP socket helpers with sane error handling.
namespace net {

// Create a listening TCP socket bound to `port` on all interfaces.
// Returns fd or -1 (with perror on failure).
inline int listen_tcp(int port, int backlog = 1) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (::bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); ::close(fd); return -1; }
    if (::listen(fd, backlog) < 0) { perror("listen"); ::close(fd); return -1; }
    return fd;
}

// Resolve host (name or dotted IP) and connect. Returns fd or -1.
inline int connect_tcp(const std::string& host, int port) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string portstr = std::to_string(port);
    int gai = getaddrinfo(host.c_str(), portstr.c_str(), &hints, &res);
    if (gai != 0) {
        std::fprintf(stderr, "resolve %s: %s\n", host.c_str(), gai_strerror(gai));
        return -1;
    }
    int fd = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) std::fprintf(stderr, "connect %s:%d failed\n", host.c_str(), port);
    return fd;
}

inline std::string peer_ip(int fd) {
    sockaddr_in a{}; socklen_t l = sizeof(a);
    if (getpeername(fd, (sockaddr*)&a, &l) != 0) return "?";
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
    return buf;
}

} // namespace net
