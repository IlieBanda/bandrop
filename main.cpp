#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include <unistd.h>
#include "version.h"
#include "discovery.h"
#include "pipe.h"
#include "serve.h"
#include "broadcast.h"
#include "receipt.h"
#include "identity.h"
#include <fstream>
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
        "  " << prog << " pipe --listen | pipe --to IP    (secure stdin<->stdout)\n"
        "  " << prog << " serve <path>...  [--port N] [--once]   (download in a browser)\n"
        "  " << prog << " broadcast <path>...              (fan-out to many receivers)\n"
        "  " << prog << " verify <receipt.json>   |   " << prog << " id\n"
        "  " << prog << " discover\n\n"
        "Commands:\n"
        "  receive     Wait for an incoming transfer (announces itself on the LAN).\n"
        "  send        Send files and/or directories. With no --to, auto-discovers\n"
        "              a receiver on the local network.\n"
        "  pipe        Secure, paired pipe between two machines (like netcat+ssh,\n"
        "              but zero-config). Composes with any Unix command.\n"
        "  serve       Share files over HTTP so any browser/phone can download them\n"
        "              (plain HTTP; LAN convenience mode). Prints a URL and QR code.\n"
        "  broadcast   Send one set of files to many receivers with a single code.\n"
        "  discover    List receivers currently waiting on the LAN.\n\n"
        "Options:\n"
        "  --to IP       Receiver address (skip LAN discovery).\n"
        "  --port N      TCP port (default " << DEFAULT_PORT << ").\n"
        "  --compress    Compress data on the fly (zlib) when sending.\n"
        "  --resume      Skip files the receiver already has (interrupted folders).\n"
        "  --out DIR     Directory to save received files into (default: current).\n"
        "  --no-announce Do not advertise this receiver over UDP discovery.\n"
        "  --overwrite   Overwrite existing files instead of auto-renaming.\n"
        "  --receipt F   (receive) Save a signed receipt of the transfer to F.\n"
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
    std::string receipt_path; take_opt(a, "--receipt", receipt_path);
    std::string from; take_opt(a, "--from", from);
    bool find_broadcast = take_flag(a, "--broadcast");
    Receiver r;
    if (find_broadcast && from.empty()) {
        std::cout << "Looking for a broadcaster on the LAN...\n";
        for (auto& p : discovery::browse(1500)) if (p.service == 1) { from = p.ip; port = p.port; break; }
        if (from.empty()) { std::cerr << "No broadcaster found. Use --from <ip>.\n"; return 1; }
    }
    if (!from.empty())
        return r.start_connect(from, port, out_dir, overwrite, receipt_path);
    return r.start(port, out_dir, announce, hostname_or("bandrop"), overwrite, receipt_path);
}

int cmd_send(std::vector<std::string> a) {
    int port = DEFAULT_PORT;
    std::string val, to;
    if (take_opt(a, "--port", val) && !parse_port(val, port)) return 1;
    take_opt(a, "--to", to);
    bool compress = take_flag(a, "--compress");
    bool resume = take_flag(a, "--resume");
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
    return s.start(to, port, a, compress, resume);
}

int cmd_discover() {
    std::cout << "Scanning the LAN for receivers...\n";
    auto peers = discovery::browse(1500);
    if (peers.empty()) { std::cout << "No receivers found.\n"; return 0; }
    for (auto& p : peers)
        std::cout << "  " << p.name << "  " << p.ip << ":" << p.port << "\n";
    return 0;
}

int cmd_pipe(std::vector<std::string> a) {
    int port = DEFAULT_PORT;
    std::string val, to, code;
    if (take_opt(a, "--port", val) && !parse_port(val, port)) return 1;
    take_opt(a, "--to", to);
    take_opt(a, "--code", code);
    bool listen = take_flag(a, "--listen");
    bool announce = !take_flag(a, "--no-announce");
    Pipe p;
    if (listen) return p.listen(port, code, announce, hostname_or("bandrop"));
    return p.connect(to, port, code);
}

int cmd_serve(std::vector<std::string> a) {
    int port = 8000;
    std::string val;
    if (take_opt(a, "--port", val) && !parse_port(val, port)) return 1;
    bool once = take_flag(a, "--once");
    if (a.empty()) { std::cerr << "serve: no files given.\n"; return 1; }
    Serve s;
    return s.start(a, port, once);
}

int cmd_verify(std::vector<std::string> a) {
    if (a.empty()) { std::cerr << "verify: give a receipt file.\n"; return 1; }
    std::ifstream in(a[0]);
    if (!in) { std::cerr << "Cannot open " << a[0] << "\n"; return 1; }
    std::string js((std::istreambuf_iterator<char>(in)), {});
    receipt::Receipt r;
    if (!receipt::from_json(js, r)) { std::cerr << "Not a valid receipt.\n"; return 1; }
    if (!receipt::verify(r)) { std::cerr << "INVALID: signature does not verify.\n"; return 1; }
    std::cout << "VALID receipt, signed by " << identity::fingerprint(r.sender_pub) << "\n";
    std::cout << "  time:  " << receipt::iso8601(r.timestamp) << "\n";
    std::cout << "  files: " << r.files.size() << "\n";
    for (auto& f : r.files)
        std::cout << "    " << f.path << "  (" << f.size << " bytes)  "
                  << receipt::to_hex(f.sha).substr(0, 16) << "...\n";
    return 0;
}

int cmd_id() {
    identity::Key k = identity::load_or_create();
    std::cout << "Your Bandrop identity:\n  fingerprint: " << identity::fingerprint(k.pub)
              << "\n  public key:  " << receipt::to_hex(k.pub) << "\n";
    return 0;
}

int cmd_broadcast(std::vector<std::string> a) {
    int port = DEFAULT_PORT;
    std::string val;
    if (take_opt(a, "--port", val) && !parse_port(val, port)) return 1;
    bool compress = take_flag(a, "--compress");
    if (a.empty()) { std::cerr << "broadcast: no files given.\n"; return 1; }
    Broadcaster b;
    return b.start(a, port, compress, hostname_or("bandrop"));
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
    if (cmd == "pipe")     return cmd_pipe(args);
    if (cmd == "serve")    return cmd_serve(args);
    if (cmd == "broadcast") return cmd_broadcast(args);
    if (cmd == "verify")   return cmd_verify(args);
    if (cmd == "id")       return cmd_id();
    if (cmd == "discover") return cmd_discover();
    std::cerr << "Unknown command: " << cmd << "\n\n";
    usage(argv[0]);
    return 1;
}
