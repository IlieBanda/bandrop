#pragma once
#include <sys/socket.h>
#include <arpa/inet.h>
#include "crypto.h"
#include <unistd.h>
#include <iostream>
#include <fstream>
#include "protocol.h"

class Receiver {
    public:
    void start(int port) {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);
        bind(server_fd, (struct sockaddr*)&address, sizeof(address));
        listen(server_fd, 3);
        std::cout << "Сервер запущен. Жду подключения к порту " << port << "...\n";
        int addrlen = sizeof(address);
        int client_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        std::cout << "Клиент успешно подключился!\n";
        std::string password;
        std::cout << "Введите 6-значный код подключения: ";
        std::cin >> password;
        AesEncryptor cryptor(password);
        unsigned char recv_buffer[4096 + 16];
        unsigned char dec_buffer[4096 + 16];
        FileHeader header;
        recv(client_socket, &header, sizeof(FileHeader), 0);
        std::cout << "Принимаю файл: " << header.filename << "\n";
        std::ofstream out_file(header.filename, std::ios::binary);
        int bytes_received;
        long total_received = 0;
        while ((bytes_received = recv(client_socket, recv_buffer, sizeof(recv_buffer), 0)) > 0) {
            int dec_len = cryptor.decrypt(recv_buffer, bytes_received, dec_buffer);
            if (dec_len == -1) {
                std::cout << "\n[ОШИБКА] Неверный код подключения!\n";
                out_file.close();
                remove(header.filename);
                close(client_socket);
                return;
            }
            out_file.write((char*)dec_buffer, dec_len);
            total_received += bytes_received;
            int percent = 0;
            if (header.filesize > 0) percent = (total_received * 100) / header.filesize;
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
        std::cout << "Файл полностью принят и расшифрован\n";
    }
};