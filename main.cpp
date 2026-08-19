#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include <unistd.h>
#include "version.h"
#include "discovery.h"
#include "receiver.h"
#include "sender.h"

namespace {

constexpr int DEFAULT_PORT = 9090;

std::string hostname_or(const std::string& fallback) {
    char h[256] = {0};
    if (gethostname(h, sizeof(h) - 1) == 0 && h[0]) return h;
    return fallback;
}

void usage(const char* prog) {
    std::cout <<
        "Bandrop - secure P2P file & folder transfer over your LAN.\n\n"
        "Usage:\n"
        "  " << prog << " receive [--port N] [--out DIR] [--no-announce]\n"
        "  " << prog << " send <path> [<path>...] [--to IP] [--port N]\n"
        "  " << prog << " discover\n\n"
        "Commands:\n"
        "  receive     Wait for an incoming transfer (announces itself on the LAN).\n"
        "  send        Send files and/or directories. With no --to, auto-discovers\n"
        "              a receiver on the local network.\n"
        "  discover    List receivers currently waiting on the LAN.\n\n"
        "Options:\n"
        "  --to IP       Receiver address (skip LAN discovery).\n"
        "  --port N      TCP port (default " << DEFAULT_PORT << ").\n"
        "  --compress    Compress data on the fly (zlib) when sending.\n"
        "  --out DIR     Directory to save received files into (default: current).\n"
        "  --no-announce Do not advertise this receiver over UDP discovery.\n"
        "  --overwrite   Overwrite existing files instead of auto-renaming.\n"
        "  -h, --help    Show this help.\n";
}

// Pull "--flag value" (or boolean "--flag") out of args.
bool take_opt(std::vector<std::string>& a, const std::string& flag, std::string& val) {
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] == flag) {
            if (i + 1 >= a.size()) return false;
            val = a[i + 1];
            a.erase(a.begin() + i, a.begin() + i + 2);
            return true;
        }
    }
    return false;
}
bool take_flag(std::vector<std::string>& a, const std::string& flag) {
    for (size_t i = 0; i < a.size(); ++i)
        if (a[i] == flag) { a.erase(a.begin() + i); return true; }
    return false;
}
bool parse_port(const std::string& s, int& port) {
    char* e = nullptr;
    long p = std::strtol(s.c_str(), &e, 10);
    if (*e || p < 1 || p > 65535) { std::cerr << "Invalid port: " << s << "\n"; return false; }
    port = (int)p; return true;
}

int cmd_receive(std::vector<std::string> a) {
    int port = DEFAULT_PORT;
    std::string val, out_dir;
    if (take_opt(a, "--port", val) && !parse_port(val, port)) return 1;
    take_opt(a, "--out", out_dir);
    bool announce = !take_flag(a, "--no-announce");
    bool overwrite = take_flag(a, "--overwrite");
    Receiver r;
    return r.start(port, out_dir, announce, hostname_or("bandrop"), overwrite);
}

int cmd_send(std::vector<std::string> a) {
    int port = DEFAULT_PORT;
    std::string val, to;
    if (take_opt(a, "--port", val) && !parse_port(val, port)) return 1;
    take_opt(a, "--to", to);
    bool compress = take_flag(a, "--compress");
    if (a.empty()) { std::cerr << "send: no files given.\n\n"; return 1; }

    if (to.empty()) {
        std::cout << "Searching for a receiver on the LAN...\n";
        auto peers = discovery::browse();
        if (peers.empty()) {
            std::cerr << "No receiver found. Start `bandrop receive` on the other "
                         "machine, or pass --to <ip>.\n";
            return 1;
        }
        to = peers.front().ip;
        port = peers.front().port;
        std::cout << "Found \"" << peers.front().name << "\" at " << to << ":" << port << ".\n";
        if (peers.size() > 1)
            std::cout << "(" << peers.size() << " receivers found; using the first. "
                         "Use --to to pick another.)\n";
    }
    Sender s;
    return s.start(to, port, a, compress);
}

int cmd_discover() {
    std::cout << "Scanning the LAN for receivers...\n";
    auto peers = discovery::browse(1500);
    if (peers.empty()) { std::cout << "No receivers found.\n"; return 0; }
    for (auto& p : peers)
        std::cout << "  " << p.name << "  " << p.ip << ":" << p.port << "\n";
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    std::signal(SIGPIPE, SIG_IGN);
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty() || args[0] == "-h" || args[0] == "--help") {
        usage(argv[0]);
        return args.empty() ? 1 : 0;
    }
    if (args[0] == "--version" || args[0] == "-V") {
        std::cout << "bandrop " << BANDROP_VERSION << "\n";
        return 0;
    }
    std::string cmd = args[0];
    args.erase(args.begin());
    if (cmd == "version") { std::cout << "bandrop " << BANDROP_VERSION << "\n"; return 0; }
    if (cmd == "receive") return cmd_receive(args);
    if (cmd == "send")    return cmd_send(args);
    if (cmd == "discover") return cmd_discover();
    std::cerr << "Unknown command: " << cmd << "\n\n";
    usage(argv[0]);
    return 1;
}
