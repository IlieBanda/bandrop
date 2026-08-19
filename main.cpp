#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include "receiver.h"
#include "sender.h"

namespace {

constexpr int DEFAULT_PORT = 9090;

void print_usage(const char* prog) {
    std::cout <<
        "Bandrop - secure P2P file transfer over your local network.\n\n"
        "Usage:\n"
        "  " << prog << " receive [--port <port>]\n"
        "  " << prog << " send <ip> <file> [--port <port>]\n\n"
        "Options:\n"
        "  --port <port>   TCP port to use (default " << DEFAULT_PORT << ")\n"
        "  -h, --help      Show this help.\n";
}

// Parse an optional --port flag out of argv, returning the port (or default)
// and removing the consumed args from `args`. Returns false on a bad value.
bool extract_port(std::vector<std::string>& args, int& port) {
    port = DEFAULT_PORT;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--port") {
            if (i + 1 >= args.size()) {
                std::cerr << "--port requires a value.\n";
                return false;
            }
            char* end = nullptr;
            long p = std::strtol(args[i + 1].c_str(), &end, 10);
            if (*end != '\0' || p < 1 || p > 65535) {
                std::cerr << "Invalid port: " << args[i + 1] << "\n";
                return false;
            }
            port = static_cast<int>(p);
            args.erase(args.begin() + i, args.begin() + i + 2);
            --i;
        }
    }
    return true;
}

} // namespace

int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty() || args[0] == "-h" || args[0] == "--help") {
        print_usage(argv[0]);
        return args.empty() ? 1 : 0;
    }

    std::string mode = args[0];
    args.erase(args.begin());

    int port = DEFAULT_PORT;
    if (!extract_port(args, port)) return 1;

    if (mode == "receive") {
        Receiver server;
        return server.start(port);
    } else if (mode == "send") {
        if (args.size() < 2) {
            std::cerr << "send requires an IP address and a file path.\n\n";
            print_usage(argv[0]);
            return 1;
        }
        Sender client;
        return client.start(args[0], port, args[1]);
    }

    std::cerr << "Unknown command: " << mode << "\n\n";
    print_usage(argv[0]);
    return 1;
}
