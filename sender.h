#pragma once
#include <unistd.h>
#include <algorithm>
#include <ctime>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "archive.h"
#include "compress.h"
#include "crypto.h"
#include "handshake.h"
#include "identity.h"
#include "net.h"
#include "protocol.h"
#include "receipt.h"
#include "session.h"
#include "ui.h"

class Sender {
public:
    // Send one or more paths (files and/or directories) to host:port.
    int start(const std::string& host, int port, const std::vector<std::string>& inputs,
              bool use_compression = false, bool resume = false) {
        std::vector<archive::Entry> entries = archive::collect(inputs);
        if (entries.empty()) {
            std::cerr << "Nothing to send (no readable files in the given paths).\n";
            return 1;
        }
        int64_t total_bytes = 0;
        for (auto& e : entries) total_bytes += (e.size > 0 ? e.size : 0);

        int fd = net::connect_tcp(host, port);
        if (fd < 0) return 1;
        std::cout << "Connected to " << host << ":" << port << ".\n";

        std::string pin = make_pin();
        std::cout << "\n=========================================\n"
                  << "  PAIRING CODE:  " << pin << "\n"
                  << "=========================================\n"
                  << "Enter this code on the receiver.\n\n" << std::flush;

        auto key = handshake::initiator(fd, pin);
        if (!key) {
            std::cerr << "[ERROR] Pairing failed: wrong code on the receiver.\n";
            ::close(fd); return 1;
        }
        std::cout << "Secure channel established.\n";
        int rc = run_transfer(fd, *key, entries, total_bytes, use_compression, false, resume);
        ::close(fd);
        return rc;
    }

    // Perform the transfer over an already-paired session. Reused by broadcast.
    // `quiet` suppresses the progress bar (for concurrent fan-out).
    static int run_transfer(int fd, const std::vector<unsigned char>& key,
                            const std::vector<archive::Entry>& entries,
                            int64_t total_bytes, bool use_compression, bool quiet,
                            bool resume = false) {
        Session sess(fd, key);

        // For resume, hash every file up front so the receiver can tell which
        // ones it already has.
        std::vector<std::vector<unsigned char>> pre_sha;
        if (resume) {
            if (!quiet) std::cout << "Hashing " << entries.size() << " file(s) for resume...\n" << std::flush;
            for (auto& e : entries) pre_sha.push_back(archive::sha256_file(e.abs_path));
        }

        proto::Writer man;
        man.u32((uint32_t)entries.size());
        man.u64((uint64_t)total_bytes);
        man.u8((use_compression ? 1 : 0) | (resume ? 2 : 0));   // bit0 zlib, bit1 resumable
        if (resume) {
            for (size_t i = 0; i < entries.size(); ++i) {
                man.str(entries[i].rel_path);
                man.u64((uint64_t)(entries[i].size > 0 ? entries[i].size : 0));
                man.blob(pre_sha[i]);
            }
        }
        if (!sess.send(proto::MSG_MANIFEST, man.buf)) return 1;

        // Determine which files to actually send.
        std::vector<char> want(entries.size(), 1);
        if (resume) {
            uint8_t t = 0; std::vector<unsigned char> pl;
            if (sess.recv(t, pl) != 1 || t != proto::MSG_NEED) return 1;
            proto::Reader nr(pl.data(), pl.size());
            std::fill(want.begin(), want.end(), 0);
            uint32_t n = nr.u32();
            int64_t need_bytes = 0; uint32_t need_files = 0;
            for (uint32_t i = 0; i < n; ++i) {
                uint32_t idx = nr.u32();
                if (nr.ok && idx < want.size()) { want[idx] = 1; need_bytes += (entries[idx].size>0?entries[idx].size:0); ++need_files; }
            }
            total_bytes = need_bytes;
            if (!quiet) std::cout << "Receiver needs " << need_files << " of " << entries.size()
                                  << " file(s) (" << ui::human_size(need_bytes) << ").\n";
        }

        if (!quiet)
            std::cout << "Sending " << entries.size() << " item(s), "
                      << ui::human_size(total_bytes) << " total.\n";

        ui::Progress bar(total_bytes);
        int64_t sent = 0;
        std::vector<unsigned char> chunk(proto::CHUNK_SIZE);
        std::vector<unsigned char> payload;
        std::vector<receipt::FileRec> recs;

        for (size_t idx = 0; idx < entries.size(); ++idx) {
            const auto& e = entries[idx];
            uint64_t esize = (uint64_t)(e.size > 0 ? e.size : 0);
            if (!want[idx]) {
                // Skipped by resume; still record it for the receipt.
                recs.push_back({e.rel_path, esize, resume ? pre_sha[idx] : std::vector<unsigned char>{}});
                continue;
            }
            std::ifstream f(e.abs_path, std::ios::binary);
            if (!f) { std::cerr << "\nSkip (cannot open): " << e.abs_path << "\n"; continue; }

            proto::Writer fh;
            fh.str(e.rel_path);
            fh.u64(esize);
            if (!sess.send(proto::MSG_FILE_START, fh.buf)) return 1;

            crypto::Sha256 hash;
            while (f) {
                f.read((char*)chunk.data(), proto::CHUNK_SIZE);
                std::streamsize got = f.gcount();
                if (got <= 0) break;
                hash.update(chunk.data(), (size_t)got);
                if (use_compression) payload = zip::deflate(chunk.data(), (size_t)got);
                else payload.assign(chunk.begin(), chunk.begin() + got);
                if (!sess.send(proto::MSG_DATA, payload)) return 1;
                sent += got;
                if (!quiet) bar.update(sent);
            }
            auto sha = hash.final();
            proto::Writer fe; fe.blob(sha);
            if (!sess.send(proto::MSG_FILE_END, fe.buf)) return 1;
            recs.push_back({e.rel_path, esize, sha});
        }

        {
            identity::Key idkey = identity::load_or_create();
            receipt::Receipt r;
            r.timestamp = (uint64_t)time(nullptr);
            r.files = recs;
            receipt::sign(r, idkey);
            std::string js = receipt::to_json(r);
            std::vector<unsigned char> pl(js.begin(), js.end());
            sess.send(proto::MSG_RECEIPT, pl);
            if (!quiet) std::cout << "Signed as " << identity::fingerprint(idkey.pub) << ".\n";
        }
        sess.send(proto::MSG_DONE, {});
        if (!quiet) { bar.finish(sent); std::cout << "Done. All items sent and verified end-to-end.\n"; }
        return 0;
    }

    static std::string make_pin() {
        unsigned char r[4]; uint32_t v = 0;
        if (crypto::random_bytes(r, 4))
            v = ((uint32_t)r[0]<<24)|((uint32_t)r[1]<<16)|((uint32_t)r[2]<<8)|r[3];
        return std::to_string(100000 + (v % 900000));
    }
};
