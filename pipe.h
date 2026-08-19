#pragma once
#include <unistd.h>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include "discovery.h"
#include "handshake.h"
#include "net.h"
#include "protocol.h"
#include "session.h"

// `bandrop pipe`: a secure, paired stdin<->stdout pipe between two machines —
// think netcat with SPAKE2 pairing and AES-GCM, no ssh and no server in the
// middle. Data flows in both directions, so it composes with any Unix tools:
//
//     # A                                  # B
//     pg_dump db | bandrop pipe --to B     bandrop pipe --listen > db.sql
//
// stdin can be occupied by piped data, so the pairing code is printed to
// stderr by the connecting side and read from the controlling terminal
// (/dev/tty) — never from stdin — by the listening side.
class Pipe {
public:
    // Connecting side (initiator). Generates a code unless one is given.
    int connect(const std::string& host, int port, std::string code) {
        int fd;
        if (host.empty()) {
            auto peers = discovery::browse();
            if (peers.empty()) { std::fprintf(stderr, "No pipe peer found on the LAN. Use --to <ip>.\n"); return 1; }
            fd = net::connect_tcp(peers.front().ip, peers.front().port);
        } else {
            fd = net::connect_tcp(host, port);
        }
        if (fd < 0) return 1;

        if (code.empty()) code = make_code();
        std::fprintf(stderr, "Pairing code: %s\n", code.c_str());
        std::fprintf(stderr, "Run on the other side:  bandrop pipe --listen   (then enter the code)\n");

        auto key = handshake::initiator(fd, code);
        if (!key) { std::fprintf(stderr, "Pairing failed (wrong code).\n"); ::close(fd); return 1; }
        std::fprintf(stderr, "Connected.\n");
        return pump(fd, *key);
    }

    // Listening side (responder). Reads the code from the terminal or --code.
    int listen(int port, std::string code, bool announce, const std::string& name) {
        int listen_fd = net::listen_tcp(port, 1);
        if (listen_fd < 0) return 1;
        int disc_fd = announce ? discovery::open_responder() : -1;
        std::fprintf(stderr, "Waiting for a pipe peer on port %d...\n", port);

        int client = accept_with_discovery(listen_fd, disc_fd, port, name);
        ::close(listen_fd);
        if (disc_fd >= 0) ::close(disc_fd);
        if (client < 0) return 1;

        if (code.empty()) {
            code = read_code_from_tty();
            if (code.empty()) {
                std::fprintf(stderr, "No code entered (and no --code); aborting.\n");
                ::close(client); return 1;
            }
        }
        auto key = handshake::responder(client, [&] { return code; });
        if (!key) { std::fprintf(stderr, "Pairing failed (wrong code).\n"); ::close(client); return 1; }
        std::fprintf(stderr, "Connected.\n");
        int rc = pump(client, *key);
        ::close(client);
        return rc;
    }

private:
    // Bidirectional pump: a background thread reads local stdin and sends it as
    // encrypted frames; the main loop decrypts incoming frames to stdout.
    static int pump(int fd, const std::vector<unsigned char>& key) {
        Session tx(fd, key);   // used only by the sender thread
        Session rx(fd, key);   // used only by this (receiver) thread
        std::atomic<bool> failed{false};

        std::thread sender([&] {
            // If stdin is an interactive terminal there is nothing to pipe in,
            // so signal "no input" immediately rather than blocking on the tty.
            if (!::isatty(STDIN_FILENO)) {
                std::vector<unsigned char> buf(64 * 1024);
                for (;;) {
                    ssize_t n = ::read(STDIN_FILENO, buf.data(), buf.size());
                    if (n <= 0) break;
                    std::vector<unsigned char> chunk(buf.begin(), buf.begin() + n);
                    if (!tx.send(proto::MSG_DATA, chunk)) { failed = true; break; }
                }
            }
            tx.send(proto::MSG_DONE, {});
        });

        int rc = 0;
        for (;;) {
            uint8_t type = 0;
            std::vector<unsigned char> payload;
            int r = rx.recv(type, payload);
            if (r == 0) break;                 // peer closed
            if (r < 0) { std::fprintf(stderr, "\n[pipe] stream error (corrupt/tampered)\n"); rc = 1; break; }
            if (type == proto::MSG_DONE) break;
            if (type == proto::MSG_DATA && !payload.empty()) {
                if (!write_all(STDOUT_FILENO, payload.data(), payload.size())) { rc = 1; break; }
            }
        }
        sender.join();
        if (failed) rc = 1;
        return rc;
    }

    static bool write_all(int fd, const unsigned char* p, size_t n) {
        while (n > 0) {
            ssize_t w = ::write(fd, p, n);
            if (w <= 0) return false;
            p += w; n -= (size_t)w;
        }
        return true;
    }

    static std::string make_code() {
        // A short numeric code is enough thanks to SPAKE2 (one online guess
        // per connection). Reuse the sender's 6-digit style for familiarity.
        unsigned char r[4]; uint32_t v = 0;
        if (crypto::random_bytes(r, 4))
            v = ((uint32_t)r[0]<<24)|((uint32_t)r[1]<<16)|((uint32_t)r[2]<<8)|r[3];
        return std::to_string(100000 + (v % 900000));
    }

    static std::string read_code_from_tty() {
        FILE* tty = std::fopen("/dev/tty", "r");
        std::fprintf(stderr, "Enter the pairing code: ");
        std::string code;
        if (tty) {
            char buf[128];
            if (std::fgets(buf, sizeof(buf), tty)) code = trim(buf);
            std::fclose(tty);
        } else {
            // No controlling terminal: fall back to stdin (non-piped use only).
            std::getline(std::cin, code);
            code = trim(code);
        }
        return code;
    }

    static std::string trim(std::string s) {
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
        size_t i = 0; while (i < s.size() && s[i] == ' ') ++i;
        return s.substr(i);
    }

    static int accept_with_discovery(int listen_fd, int disc_fd, int port, const std::string& name) {
        for (;;) {
            fd_set rs; FD_ZERO(&rs);
            FD_SET(listen_fd, &rs);
            int maxfd = listen_fd;
            if (disc_fd >= 0) { FD_SET(disc_fd, &rs); if (disc_fd > maxfd) maxfd = disc_fd; }
            if (::select(maxfd + 1, &rs, nullptr, nullptr, nullptr) < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            if (disc_fd >= 0 && FD_ISSET(disc_fd, &rs))
                discovery::answer_query(disc_fd, port, name);
            if (FD_ISSET(listen_fd, &rs))
                return ::accept(listen_fd, nullptr, nullptr);
        }
    }
};
