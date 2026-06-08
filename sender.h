#pragma once
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include "crypto.h"
#include "protocol.h"
#include <cstdlib>
#include <ctime>

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
        srand(time(NULL));
        int random_code = 100000 + rand() % 900000;
        std::string password = std::to_string(random_code);
        std::cout << "\n=========================================\n";
        std::cout << " КОД ПОДКЛЮЧЕНИЯ: " << password << "\n";
        std::cout << "=========================================\n";
        std::cout << "Жду, пока получатель введет код...\n";
        AesEncryptor cryptor(password);
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
        std::ifstream file(filepath, std::ios::binary);
        file.seekg(0, std::ios::end);
        long filesize = file.tellg();
        file.seekg(0, std::ios::beg);
        header.filesize = filesize;
        send(sock, &header, sizeof(FileHeader), 0);
        unsigned char buffer[4096];
        unsigned char enc_buffer[4096 + 16];
        long total_sent = 0;
        while (file.read((char*)buffer, sizeof(buffer)) || file.gcount() > 0) {
            int bytes_read = file.gcount();
            int enc_len = cryptor.encrypt(buffer, bytes_read, enc_buffer);
            send(sock, enc_buffer, enc_len, 0);
            total_sent += bytes_read;
            int percent = 0;
            if (filesize > 0) percent = (total_sent * 100) / filesize;
            std::cout << "\r[";
            for (int i = 0; i < 50; i++) {
                if (i < percent / 2) std::cout << "=";
                else if (i == percent / 2) std::cout << ">";
                else std::cout << " ";
            }
            std::cout << "] " << percent << "%";
            std::cout.flush();
        }
        std::cout << "\n";
        std::cout << "Файл полностью зашифрован и отправлен!\n";
    }
};