#pragma once
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "crypto.h"
#include "protocol.h"
#include "ui.h"

class Sender {
public:
    // Returns 0 on success, non-zero on failure.
    int start(const std::string& ip, int port, const std::string& filepath) {
        // Open and size the file up front so we fail before connecting.
        std::ifstream file(filepath, std::ios::binary | std::ios::ate);
        if (!file) {
            std::cerr << "Cannot open file: " << filepath << "\n";
            return 1;
        }
        int64_t filesize = static_cast<int64_t>(file.tellg());
        file.seekg(0, std::ios::beg);

        int sock = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { perror("socket"); return 1; }

        sockaddr_in serv{};
        serv.sin_family = AF_INET;
        serv.sin_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET, ip.c_str(), &serv.sin_addr) != 1) {
            std::cerr << "Invalid IP address: " << ip << "\n";
            ::close(sock);
            return 1;
        }
        if (::connect(sock, reinterpret_cast<sockaddr*>(&serv), sizeof(serv)) < 0) {
            perror("connect");
            ::close(sock);
            return 1;
        }
        std::cout << "Connected to " << ip << ":" << port << ".\n";

        // Generate a random session salt and a 6-digit pairing code.
        unsigned char salt[AesEncryptor::SALT_LEN];
        if (!AesEncryptor::random_bytes(salt, sizeof(salt))) {
            std::cerr << "Failed to generate random salt.\n";
            ::close(sock);
            return 1;
        }
        std::string password = make_pin();
        std::cout << "\n=========================================\n"
                  << "  PAIRING CODE: " << password << "\n"
                  << "=========================================\n"
                  << "Share this code with the receiver.\n";

        AesEncryptor cryptor(password, salt);

        // 1. Send the salt (plaintext) so the receiver can derive the key.
        if (!send_all(sock, salt, sizeof(salt))) {
            std::cerr << "Failed to send handshake.\n";
            ::close(sock);
            return 1;
        }

        // 2. Send the encrypted header.
        FileHeader header{};
        std::string name = safe_basename(filepath);
        std::strncpy(header.filename, name.c_str(), sizeof(header.filename) - 1);
        header.filesize = filesize;

        std::vector<unsigned char> enc(AesEncryptor::IV_LEN + sizeof(FileHeader) + 32);
        int elen = cryptor.encrypt(reinterpret_cast<unsigned char*>(&header),
                                   sizeof(FileHeader), enc.data());
        if (elen < 0 || !send_frame(sock, enc.data(), static_cast<uint32_t>(elen))) {
            std::cerr << "Failed to send file header.\n";
            ::close(sock);
            return 1;
        }

        // 3. Stream the file in encrypted, length-framed chunks.
        std::vector<unsigned char> buffer(CHUNK_SIZE);
        std::vector<unsigned char> encbuf(AesEncryptor::IV_LEN + CHUNK_SIZE + 32);
        int64_t sent = 0;
        std::cout << "Sending \"" << name << "\" (" << human_size(filesize) << ")...\n";
        while (file) {
            file.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
            std::streamsize got = file.gcount();
            if (got <= 0) break;
            elen = cryptor.encrypt(buffer.data(), static_cast<int>(got), encbuf.data());
            if (elen < 0 || !send_frame(sock, encbuf.data(), static_cast<uint32_t>(elen))) {
                std::cerr << "\nFailed to send data.\n";
                ::close(sock);
                return 1;
            }
            sent += got;
            draw_progress(sent, filesize);
        }
        std::cout << "\n";
        ::close(sock);

        if (sent != filesize) {
            std::cerr << "[WARNING] Only sent " << human_size(sent)
                      << " of " << human_size(filesize) << ".\n";
            return 1;
        }
        std::cout << "Done. Sent and encrypted successfully.\n";
        return 0;
    }

private:
    static std::string make_pin() {
        unsigned char r[4];
        uint32_t v = 0;
        if (AesEncryptor::random_bytes(r, sizeof(r))) {
            v = (uint32_t(r[0]) << 24) | (uint32_t(r[1]) << 16) |
                (uint32_t(r[2]) << 8) | uint32_t(r[3]);
        }
        return std::to_string(100000 + (v % 900000));
    }
};
