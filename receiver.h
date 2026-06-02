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

        AesEncryptor cryptor;
        unsigned char recv_buffer[4096 + 16];
        unsigned char dec_buffer[4096 + 16];
        FileHeader header;
        recv(client_socket, &header, sizeof(FileHeader), 0);
        std::cout << "Принимаю файл: " << header.filename << "\n";
        std::ofstream out_file(header.filename, std::ios::binary);
        int bytes_received;
        while ((bytes_received = recv(client_socket, recv_buffer, sizeof(recv_buffer), 0)) > 0) {
            int dec_len = cryptor.decrypt(recv_buffer, bytes_received, dec_buffer);
            out_file.write((char*)dec_buffer, dec_len);
        }
        std::cout << "Файл полностью принят и расшифрован\n";
    }
};