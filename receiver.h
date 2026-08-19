#pragma once
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "crypto.h"
#include "protocol.h"
#include "ui.h"

class Receiver {
public:
    // Returns 0 on success, non-zero on failure.
    int start(int port) {
        int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) { perror("socket"); return 1; }

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(static_cast<uint16_t>(port));

        if (::bind(server_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
            perror("bind");
            ::close(server_fd);
            return 1;
        }
        if (::listen(server_fd, 1) < 0) {
            perror("listen");
            ::close(server_fd);
            return 1;
        }

        std::cout << "Listening on port " << port << ", waiting for a sender...\n";
        socklen_t addrlen = sizeof(address);
        int client = ::accept(server_fd, reinterpret_cast<sockaddr*>(&address), &addrlen);
        ::close(server_fd);
        if (client < 0) { perror("accept"); return 1; }

        char peer[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &address.sin_addr, peer, sizeof(peer));
        std::cout << "Sender connected from " << peer << ".\n";

        int rc = receive(client);
        ::close(client);
        return rc;
    }

private:
    int receive(int client) {
        // 1. Receive the session salt.
        unsigned char salt[AesEncryptor::SALT_LEN];
        if (!recv_all(client, salt, sizeof(salt))) {
            std::cerr << "Connection closed during handshake.\n";
            return 1;
        }

        // 2. Prompt for the pairing code and derive the key.
        std::string password;
        std::cout << "Enter the 6-digit pairing code: ";
        if (!(std::cin >> password)) return 1;
        AesEncryptor cryptor(password, salt);

        std::vector<unsigned char> frame(MAX_FRAME);
        std::vector<unsigned char> plain(MAX_FRAME);

        // 3. First frame is the encrypted file header; failure means wrong PIN.
        uint32_t flen = 0;
        if (recv_frame(client, frame.data(), frame.size(), &flen) != 1) {
            std::cerr << "Failed to receive file header.\n";
            return 1;
        }
        int plen = cryptor.decrypt(frame.data(), static_cast<int>(flen), plain.data());
        if (plen != sizeof(FileHeader)) {
            std::cerr << "\n[ERROR] Wrong pairing code (or corrupt stream).\n";
            return 1;
        }
        FileHeader header;
        std::memcpy(&header, plain.data(), sizeof(FileHeader));
        header.filename[sizeof(header.filename) - 1] = '\0';
        std::string out_name = safe_basename(header.filename);

        std::cout << "Receiving \"" << out_name << "\" ("
                  << human_size(header.filesize) << ")...\n";

        std::ofstream out(out_name, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "Cannot open output file: " << out_name << "\n";
            return 1;
        }

        // 4. Stream the remaining frames.
        int64_t received = 0;
        while (true) {
            int r = recv_frame(client, frame.data(), frame.size(), &flen);
            if (r == 0) break;             // clean EOF
            if (r < 0) {
                std::cerr << "\nConnection error during transfer.\n";
                out.close();
                ::remove(out_name.c_str());
                return 1;
            }
            plen = cryptor.decrypt(frame.data(), static_cast<int>(flen), plain.data());
            if (plen < 0) {
                std::cerr << "\n[ERROR] Decryption failed (corrupt or tampered data).\n";
                out.close();
                ::remove(out_name.c_str());
                return 1;
            }
            out.write(reinterpret_cast<char*>(plain.data()), plen);
            received += plen;
            draw_progress(received, header.filesize);
        }
        out.close();
        std::cout << "\n";

        if (header.filesize >= 0 && received != header.filesize) {
            std::cerr << "[WARNING] Incomplete transfer: got "
                      << human_size(received) << " of "
                      << human_size(header.filesize) << ".\n";
            return 1;
        }
        std::cout << "Done. Saved to \"" << out_name << "\".\n";
        return 0;
    }
};
