#pragma once
#include <sys/select.h>
#include <unistd.h>
#include <atomic>
#include <cerrno>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "archive.h"
#include "discovery.h"
#include "handshake.h"
#include "net.h"
#include "sender.h"

// `bandrop broadcast`: fan-out one set of files to many receivers with a single
// code. The broadcaster listens (and announces itself as a broadcaster on the
// LAN); each receiver connects, pairs with the same code, and gets its own
// encrypted copy. Still fully peer-to-peer — no server in the middle.
class Broadcaster {
public:
    int start(const std::vector<std::string>& inputs, int port, bool use_compression,
              const std::string& name) {
        entries_ = archive::collect(inputs);
        if (entries_.empty()) { std::cerr << "Nothing to broadcast.\n"; return 1; }
        for (auto& e : entries_) total_bytes_ += (e.size > 0 ? e.size : 0);
        compress_ = use_compression;
        code_ = Sender::make_pin();

        int listen_fd = net::listen_tcp(port, 16);
        if (listen_fd < 0) return 1;
        int disc_fd = discovery::open_responder();

        std::cout << "\n=========================================\n"
                  << "  BROADCAST CODE:  " << code_ << "\n"
                  << "=========================================\n"
                  << "On each device run:  bandrop receive --broadcast\n"
                  << "(or `bandrop receive --from " << name << "`), then enter the code.\n\n"
                  << "Sharing " << entries_.size() << " item(s), "
                  << ui::human_size(total_bytes_) << " each. Press Ctrl-C to stop.\n" << std::flush;

        for (;;) {
            fd_set rs; FD_ZERO(&rs);
            FD_SET(listen_fd, &rs);
            int maxfd = listen_fd;
            if (disc_fd >= 0) { FD_SET(disc_fd, &rs); if (disc_fd > maxfd) maxfd = disc_fd; }
            if (::select(maxfd + 1, &rs, nullptr, nullptr, nullptr) < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (disc_fd >= 0 && FD_ISSET(disc_fd, &rs))
                discovery::answer_query(disc_fd, port, name, /*service=*/1);
            if (FD_ISSET(listen_fd, &rs)) {
                int c = ::accept(listen_fd, nullptr, nullptr);
                if (c >= 0) std::thread(&Broadcaster::serve_one, this, c).detach();
            }
        }
        ::close(listen_fd);
        if (disc_fd >= 0) ::close(disc_fd);
        return 0;
    }

private:
    std::vector<archive::Entry> entries_;
    int64_t total_bytes_ = 0;
    bool compress_ = false;
    std::string code_;
    std::mutex log_;
    std::atomic<int> count_{0};

    void serve_one(int fd) {
        std::string peer = net::peer_ip(fd);
        auto key = handshake::initiator(fd, code_);
        if (!key) {
            std::lock_guard<std::mutex> lk(log_);
            std::cout << "  " << peer << ": wrong code, skipped.\n" << std::flush;
            ::close(fd); return;
        }
        int rc = Sender::run_transfer(fd, *key, entries_, total_bytes_, compress_, /*quiet=*/true);
        ::close(fd);
        int n = ++count_;
        std::lock_guard<std::mutex> lk(log_);
        std::cout << "  " << peer << ": " << (rc == 0 ? "delivered" : "FAILED")
                  << "  (total delivered: " << n << ")\n" << std::flush;
    }
};
