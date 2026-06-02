#pragma once
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include "crypto.h"
#include "protocol.h"

class Sender {
    public:
    void start(std::string ip, int port, std::string filepath) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr);
        connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        std::cout << "Уcпешно подключился к серверу!\n";
        AesEncryptor cryptor;
        if (filepath.front() == '\'') {
            filepath.erase(0, 1);
        }
        if (filepath.back() == '\'') {
            filepath.pop_back();
        }
        size_t last_slash = filepath.find_last_of('/');
        std::string clean_name = filepath.substr(last_slash + 1);
        FileHeader header;
        strncpy(header.filename, clean_name.c_str(), 255);
        send(sock, &header, sizeof(FileHeader), 0);
        std::ifstream file(filepath, std::ios::binary);
        unsigned char buffer[4096];
        unsigned char enc_buffer[4096 + 16];
        while (file.read((char*)buffer, sizeof(buffer)) || file.gcount() > 0) {
            int bytes_read = file.gcount();
            int enc_len = cryptor.encrypt(buffer, bytes_read, enc_buffer);
            send(sock, enc_buffer, enc_len, 0);
        }
        std::cout << "Файл полностью зашифрован и отправлен!\n";
    }
};