#pragma once
#include <sys/select.h>
#include <cerrno>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "archive.h"
#include "compress.h"
#include "crypto.h"
#include "discovery.h"
#include "handshake.h"
#include "receipt.h"
#include "net.h"
#include "protocol.h"
#include "session.h"
#include "spake2.h"
#include "ui.h"

class Receiver {
public:
    // set via start()

    // Listen on `port`, save incoming files under `out_dir`. When `announce`
    // is set, answer LAN discovery queries while waiting.
    int start(int port, const std::string& out_dir, bool announce, const std::string& name,
              bool overwrite = false, const std::string& receipt_path = "") {
        overwrite_ = overwrite;
        receipt_path_ = receipt_path;
        int listen_fd = net::listen_tcp(port, 1);
        if (listen_fd < 0) return 1;

        int disc_fd = -1;
        if (announce) {
            disc_fd = discovery::open_responder();
            std::cout << (disc_fd >= 0
                ? "Discoverable on the LAN as \"" + name + "\".\n"
                : "(discovery unavailable; senders must use the IP)\n");
        }
        std::cout << "Listening on port " << port << ", waiting for a sender...\n";

        int client = wait_for_client(listen_fd, disc_fd, port, name);
        ::close(listen_fd);
        if (disc_fd >= 0) ::close(disc_fd);
        if (client < 0) return 1;

        std::cout << "Sender connected from " << net::peer_ip(client) << ".\n";
        int rc = handle(client, out_dir);
        ::close(client);
        return rc;
    }

    // Connect to a broadcaster (fan-out) and receive, using a known code.
    int start_connect(const std::string& host, int port, const std::string& out_dir,
                      bool overwrite, const std::string& receipt_path) {
        overwrite_ = overwrite;
        receipt_path_ = receipt_path;
        int fd = net::connect_tcp(host, port);
        if (fd < 0) return 1;
        std::cout << "Connected to broadcaster " << host << ":" << port << ".\n";
        int rc = handle(fd, out_dir);
        ::close(fd);
        return rc;
    }

private:
    bool overwrite_ = false;
    std::string receipt_path_;
    // Accept a TCP connection, answering discovery queries meanwhile.
    int wait_for_client(int listen_fd, int disc_fd, int port, const std::string& name) {
        for (;;) {
            fd_set rs; FD_ZERO(&rs);
            FD_SET(listen_fd, &rs);
            int maxfd = listen_fd;
            if (disc_fd >= 0) { FD_SET(disc_fd, &rs); if (disc_fd > maxfd) maxfd = disc_fd; }
            if (::select(maxfd + 1, &rs, nullptr, nullptr, nullptr) < 0) {
                if (errno == EINTR) continue;
                perror("select"); return -1;
            }
            if (disc_fd >= 0 && FD_ISSET(disc_fd, &rs))
                discovery::answer_query(disc_fd, port, name);
            if (FD_ISSET(listen_fd, &rs))
                return ::accept(listen_fd, nullptr, nullptr);
        }
    }

    int handle(int fd, const std::string& out_dir) {
        // --- SPAKE2 handshake -------------------------------------------
        auto key = handshake::responder(
            fd,
            [] { std::string pin; std::cout << "Enter the pairing code: ";
                 std::cin >> pin; return pin; },
            [](uint16_t ver) {
                std::cerr << "Protocol mismatch (sender v" << ver
                          << ", we speak v" << proto::PROTOCOL_VERSION << ").\n"; });
        if (!key) { std::cerr << "[ERROR] Pairing failed: wrong code.\n"; return 1; }
        std::cout << "Secure channel established.\n";

        // --- receive ----------------------------------------------------
        Session sess(fd, *key);
        int64_t total_bytes = 0;
        uint32_t total_files = 0;
        bool compressed = false;
        int64_t received = 0;
        ui::Progress* bar = nullptr;

        std::ofstream out;
        std::string cur_name;
        int64_t cur_expected = 0, cur_written = 0;
        crypto::Sha256* cur_hash = nullptr;
        int files_done = 0;

        auto cleanup_cur = [&]() {
            if (out.is_open()) out.close();
            delete cur_hash; cur_hash = nullptr;
        };

        for (;;) {
            uint8_t type = 0;
            std::vector<unsigned char> payload;
            int r = sess.recv(type, payload);
            if (r == 0) { std::cerr << "\nConnection closed unexpectedly.\n"; cleanup_cur(); delete bar; return 1; }
            if (r < 0) { std::cerr << "\n[ERROR] Corrupt or tampered data — aborting.\n"; cleanup_cur(); delete bar; return 1; }
            proto::Reader pr(payload.data(), payload.size());

            if (type == proto::MSG_MANIFEST) {
                total_files = pr.u32();
                total_bytes = (int64_t)pr.u64();
                compressed = (pr.u8() & 1) != 0;
                std::cout << "Incoming: " << total_files << " item(s), "
                          << ui::human_size(total_bytes) << " total.\n";
                bar = new ui::Progress(total_bytes);
            } else if (type == proto::MSG_FILE_START) {
                cleanup_cur();
                std::string rel = proto::safe_relpath(pr.str());
                cur_expected = (int64_t)pr.u64();
                if (!pr.ok) { std::cerr << "\nMalformed file header.\n"; delete bar; return 1; }
                std::string full = out_dir.empty() ? rel : out_dir + "/" + rel;
                archive::make_parent_dirs(out_dir.empty() ? "." : out_dir, rel);
                if (!overwrite_) {
                    std::string uniq = archive::unique_path(full);
                    if (uniq != full)
                        std::cout << "\n(exists) saving as " << uniq << "\n";
                    full = uniq;
                }
                out.open(full, std::ios::binary | std::ios::trunc);
                if (!out) { std::cerr << "\nCannot write: " << full << "\n"; delete bar; return 1; }
                cur_name = full; cur_written = 0;
                cur_hash = new crypto::Sha256();
            } else if (type == proto::MSG_DATA) {
                if (!out.is_open()) { std::cerr << "\nProtocol error (data before file).\n"; delete bar; return 1; }
                const unsigned char* raw = payload.data();
                size_t raw_len = payload.size();
                std::vector<unsigned char> inflated;
                if (compressed) {
                    try { inflated = zip::inflate(payload.data(), payload.size()); }
                    catch (const std::exception& e) {
                        std::cerr << "\n[ERROR] Decompression failed: " << e.what() << "\n";
                        cleanup_cur(); delete bar; return 1;
                    }
                    raw = inflated.data(); raw_len = inflated.size();
                }
                out.write((const char*)raw, raw_len);
                cur_hash->update(raw, raw_len);
                cur_written += (int64_t)raw_len;
                received += (int64_t)raw_len;
                if (bar) bar->update(received);
            } else if (type == proto::MSG_FILE_END) {
                auto want = pr.blob();
                auto got = cur_hash->final();
                out.close();
                delete cur_hash; cur_hash = nullptr;
                if (want != got) {
                    std::cerr << "\n[ERROR] Integrity check failed for " << cur_name << ".\n";
                    delete bar; return 1;
                }
                if (cur_expected >= 0 && cur_written != cur_expected)
                    std::cerr << "\n[WARNING] Size mismatch for " << cur_name << ".\n";
                ++files_done;
            } else if (type == proto::MSG_RECEIPT) {
                std::string js((const char*)payload.data(), payload.size());
                receipt::Receipt rc;
                if (receipt::from_json(js, rc) && receipt::verify(rc)) {
                    std::cout << "\nReceipt signed by " << identity::fingerprint(rc.sender_pub)
                              << " (verified).\n";
                    if (!receipt_path_.empty()) {
                        std::ofstream rf(receipt_path_, std::ios::trunc);
                        rf << receipt::to_json(rc) << "\n";
                        std::cout << "Receipt written to " << receipt_path_ << ".\n";
                    }
                } else {
                    std::cerr << "\n[WARNING] Transfer receipt failed verification.\n";
                }
            } else if (type == proto::MSG_DONE) {
                break;
            }
        }
        cleanup_cur();
        if (bar) bar->finish(received);
        delete bar;
        std::cout << "Done. Received and verified " << files_done << " file(s)"
                  << (out_dir.empty() ? "" : " into \"" + out_dir + "/\"") << ".\n";
        return 0;
    }
};
