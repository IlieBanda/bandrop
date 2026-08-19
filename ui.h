#pragma once
#include <cstdint>
#include <iostream>
#include <string>

// A minimal terminal progress bar shared by sender and receiver.
inline void draw_progress(int64_t done, int64_t total) {
    int percent = 0;
    if (total > 0) {
        percent = static_cast<int>((done * 100) / total);
        if (percent > 100) percent = 100;
    }
    const int width = 50;
    int filled = percent * width / 100;
    std::cout << "\r[";
    for (int i = 0; i < width; i++) {
        if (i < filled) std::cout << '=';
        else if (i == filled) std::cout << '>';
        else std::cout << ' ';
    }
    std::cout << "] " << percent << "%" << std::flush;
}

// Human-readable byte count, e.g. "3.2 MiB".
inline std::string human_size(int64_t bytes) {
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = static_cast<double>(bytes);
    int u = 0;
    while (v >= 1024.0 && u < 4) { v /= 1024.0; u++; }
    char buf[64];
    if (u == 0) snprintf(buf, sizeof(buf), "%lld %s", static_cast<long long>(bytes), units[u]);
    else snprintf(buf, sizeof(buf), "%.1f %s", v, units[u]);
    return buf;
}
