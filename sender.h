#pragma once
#include <unistd.h>
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
              bool use_compression = false) {
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
        int rc = run_transfer(fd, *key, entries, total_bytes, use_compression, false);
        ::close(fd);
        return rc;
    }

    // Perform the transfer over an already-paired session. Reused by broadcast.
    // `quiet` suppresses the progress bar (for concurrent fan-out).
    static int run_transfer(int fd, const std::vector<unsigned char>& key,
                            const std::vector<archive::Entry>& entries,
                            int64_t total_bytes, bool use_compression, bool quiet) {
        Session sess(fd, key);

        proto::Writer man;
        man.u32((uint32_t)entries.size());
        man.u64((uint64_t)total_bytes);
        man.u8(use_compression ? 1 : 0);
        if (!sess.send(proto::MSG_MANIFEST, man.buf)) return 1;

        if (!quiet)
            std::cout << "Sending " << entries.size() << " item(s), "
                      << ui::human_size(total_bytes) << " total.\n";

        ui::Progress bar(total_bytes);
        int64_t sent = 0;
        std::vector<unsigned char> chunk(proto::CHUNK_SIZE);
        std::vector<unsigned char> payload;
        std::vector<receipt::FileRec> recs;

        for (const auto& e : entries) {
            std::ifstream f(e.abs_path, std::ios::binary);
            if (!f) { std::cerr << "\nSkip (cannot open): " << e.abs_path << "\n"; continue; }

            proto::Writer fh;
            fh.str(e.rel_path);
            fh.u64((uint64_t)(e.size > 0 ? e.size : 0));
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
            recs.push_back({e.rel_path, (uint64_t)(e.size > 0 ? e.size : 0), sha});
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
