#include <iostream>
#include <string>
#include "crypto.h"
#include "receiver.h"
#include "sender.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Использование: ./drop receive ИЛИ ./drop send <ip>\n";
        return 1;
    }
    
    std::string mode = argv[1];
    if (mode == "receive") {
        std::cout << "Запуск в режиме сервера (Receiver)...\n";
        Receiver server;
        server.start(9090);
    } else if (mode == "send") {
        std::cout << "Запуск в режиме клиента (Sender)...\n";
        std::string path;
        std::cout << "Перетащите файл в терминал и нажмите Enter...\n";
        std::cin.ignore();
        std::getline(std::cin, path);
        Sender client;
        client.start("127.0.0.1", 9090, path);
    } else {
        std::cout << "Неизвестный режим!\n";
    }
    return 0;
}