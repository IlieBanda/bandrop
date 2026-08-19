#pragma once
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <atomic>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <vector>
#include "archive.h"
#include "crypto.h"
#include "net.h"
#include "protocol.h"
#include "qr.h"
#include "ui.h"

// `bandrop serve`: expose files over a tiny HTTP server so any device with a
// browser can download them — no app to install on the other end. Prints a URL
// and a scannable QR code. This is the LAN convenience mode: unlike send/pipe
// it is plain HTTP (no pairing/encryption), so use it on networks you trust.
class Serve {
public:
    int start(const std::vector<std::string>& inputs, int port, bool once) {
        entries_ = archive::collect(inputs);
        // Only regular files can be served.
        std::vector<archive::Entry> files;
        for (auto& e : entries_) if (archive::is_reg(e.abs_path)) files.push_back(e);
        entries_ = files;
        if (entries_.empty()) { std::cerr << "Nothing to serve.\n"; return 1; }
        once_ = once;

        token_ = hextoken(4);
        int fd = net::listen_tcp(port, 16);
        if (fd < 0) return 1;

        std::string ip = local_ip();
        std::string url = "http://" + ip + ":" + std::to_string(port) + "/" + token_ + "/";
        std::cout << "\nServing " << entries_.size() << " file(s). Open on any device:\n\n";
        std::cout << "  " << url << "\n\n";
        auto qr = qr::encode(url, qr::M);
        if (!qr.empty()) std::cout << qr::to_ascii(qr) << "\n";
        std::cout << (once_ ? "Will stop after the first completed download. " : "")
                  << "Press Ctrl-C to stop.\n" << std::flush;

        for (;;) {
            int c = ::accept(fd, nullptr, nullptr);
            if (c < 0) continue;
            if (once_) { handle(c); ::close(c); if (served_ok_) break; }
            else std::thread([this, c] { handle(c); ::close(c); }).detach();
        }
        ::close(fd);
        return 0;
    }

private:
    std::vector<archive::Entry> entries_;
    std::string token_;
    bool once_ = false;
    std::atomic<bool> served_ok_{false};

    static std::string hextoken(int nbytes) {
        auto r = crypto::random_vec(nbytes);
        static const char* h = "0123456789abcdef";
        std::string s;
        for (unsigned char b : r) { s += h[b >> 4]; s += h[b & 15]; }
        return s;
    }

    // First non-loopback IPv4 address, or 127.0.0.1.
    static std::string local_ip() {
        ifaddrs* ifap = nullptr;
        std::string best = "127.0.0.1";
        if (getifaddrs(&ifap) != 0) return best;
        for (ifaddrs* p = ifap; p; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
            if (!(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
            char buf[INET_ADDRSTRLEN] = {0};
            auto* sa = (sockaddr_in*)p->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
            best = buf;
            break;
        }
        freeifaddrs(ifap);
        return best;
    }

    static std::string url_decode(const std::string& s) {
        std::string out;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '%' && i + 2 < s.size()) {
                auto hex = [](char c)->int {
                    if (c>='0'&&c<='9') return c-'0';
                    if (c>='a'&&c<='f') return c-'a'+10;
                    if (c>='A'&&c<='F') return c-'A'+10;
                    return 0;
                };
                out += char(hex(s[i+1]) * 16 + hex(s[i+2])); i += 2;
            } else if (s[i] == '+') out += ' ';
            else out += s[i];
        }
        return out;
    }

    static std::string html_escape(const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '&') o += "&amp;"; else if (c == '<') o += "&lt;";
            else if (c == '>') o += "&gt;"; else if (c == '"') o += "&quot;"; else o += c;
        }
        return o;
    }

    static const char* mime(const std::string& name) {
        auto ends = [&](const char* e) {
            size_t n = std::string(e).size();
            return name.size() >= n && name.compare(name.size()-n, n, e) == 0; };
        if (ends(".html")||ends(".htm")) return "text/html";
        if (ends(".txt")||ends(".md")) return "text/plain; charset=utf-8";
        if (ends(".png")) return "image/png";
        if (ends(".jpg")||ends(".jpeg")) return "image/jpeg";
        if (ends(".gif")) return "image/gif";
        if (ends(".pdf")) return "application/pdf";
        if (ends(".mp4")) return "video/mp4";
        if (ends(".zip")) return "application/zip";
        return "application/octet-stream";
    }

    void send_response(int fd, const std::string& status, const std::string& ctype,
                       const std::string& body) {
        std::string h = "HTTP/1.1 " + status + "\r\n"
            "Content-Type: " + ctype + "\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "Connection: close\r\n\r\n";
        proto::send_all(fd, h.data(), h.size());
        proto::send_all(fd, body.data(), body.size());
    }

    void handle(int fd) {
        std::string req;
        char buf[2048];
        for (;;) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) return;
            req.append(buf, n);
            if (req.find("\r\n\r\n") != std::string::npos || req.size() > 8192) break;
        }
        if (req.compare(0, 4, "GET ") != 0) { send_response(fd, "400 Bad Request", "text/plain", "bad request\n"); return; }
        size_t sp = req.find(' ', 4);
        std::string path = url_decode(req.substr(4, sp - 4));
        std::string prefix = "/" + token_ + "/";

        if (path == "/" + token_ || path == prefix) { serve_index(fd, prefix); return; }
        if (path.compare(0, prefix.size(), prefix) == 0) {
            std::string rel = path.substr(prefix.size());
            for (auto& e : entries_) {
                if (e.rel_path == rel) { serve_file(fd, e); return; }
            }
        }
        send_response(fd, "404 Not Found", "text/plain", "not found\n");
    }

    void serve_index(int fd, const std::string& prefix) {
        std::string b = "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>Bandrop</title><style>body{font-family:system-ui,sans-serif;max-width:40rem;"
            "margin:2rem auto;padding:0 1rem}h1{font-size:1.4rem}a{display:block;padding:.6rem .2rem;"
            "border-bottom:1px solid #ddd;text-decoration:none;color:#0366d6}small{color:#666}</style>"
            "<h1>Bandrop &mdash; available files</h1>";
        for (auto& e : entries_) {
            b += "<a href='" + prefix + html_escape(e.rel_path) + "'>" + html_escape(e.rel_path) +
                 " <small>(" + ui::human_size(e.size) + ")</small></a>";
        }
        send_response(fd, "200 OK", "text/html; charset=utf-8", b);
    }

    void serve_file(int fd, const archive::Entry& e) {
        std::ifstream in(e.abs_path, std::ios::binary);
        if (!in) { send_response(fd, "404 Not Found", "text/plain", "gone\n"); return; }
        int64_t size = archive::file_size(e.abs_path);
        std::string base = archive::basename_of(e.rel_path);
        std::string h = "HTTP/1.1 200 OK\r\n"
            "Content-Type: " + std::string(mime(base)) + "\r\n"
            "Content-Length: " + std::to_string(size) + "\r\n"
            "Content-Disposition: attachment; filename=\"" + base + "\"\r\n"
            "Connection: close\r\n\r\n";
        if (!proto::send_all(fd, h.data(), h.size())) return;
        std::vector<char> chunk(128 * 1024);
        int64_t sent = 0;
        while (in) {
            in.read(chunk.data(), chunk.size());
            std::streamsize got = in.gcount();
            if (got <= 0) break;
            if (!proto::send_all(fd, chunk.data(), got)) return;
            sent += got;
        }
        if (sent == size) { served_ok_ = true; std::cout << "Downloaded: " << e.rel_path << "\n" << std::flush; }
    }
};
