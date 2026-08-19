#pragma once
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>

// Terminal presentation helpers: human sizes and a live progress bar with
// transfer rate and ETA.
namespace ui {

inline std::string human_size(int64_t bytes) {
    const char* u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = (double)bytes; int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; ++i; }
    char b[64];
    if (i == 0) std::snprintf(b, sizeof(b), "%lld %s", (long long)bytes, u[i]);
    else std::snprintf(b, sizeof(b), "%.1f %s", v, u[i]);
    return b;
}

inline std::string human_rate(double bytes_per_sec) {
    return human_size((int64_t)bytes_per_sec) + "/s";
}

inline std::string human_time(double sec) {
    if (sec < 0 || sec > 359999) return "--:--";
    int s = (int)(sec + 0.5);
    char b[32];
    if (s >= 3600) std::snprintf(b, sizeof(b), "%d:%02d:%02d", s/3600, (s%3600)/60, s%60);
    else std::snprintf(b, sizeof(b), "%02d:%02d", s/60, s%60);
    return b;
}

// A progress bar that computes rate/ETA from a start timestamp.
class Progress {
public:
    explicit Progress(int64_t total) : total_(total), start_(clock::now()) {}

    void update(int64_t done) {
        auto now = clock::now();
        double elapsed = std::chrono::duration<double>(now - start_).count();
        // Throttle redraws to ~20 fps.
        double since = std::chrono::duration<double>(now - last_draw_).count();
        if (done < total_ && since < 0.05) return;
        last_draw_ = now;

        int pct = 0;
        if (total_ > 0) { pct = (int)((done * 100) / total_); if (pct > 100) pct = 100; }
        const int width = 40;
        int filled = pct * width / 100;
        std::cout << "\r[";
        for (int i = 0; i < width; ++i)
            std::cout << (i < filled ? '=' : (i == filled ? '>' : ' '));
        double rate = elapsed > 0 ? done / elapsed : 0;
        double eta = rate > 0 && total_ > done ? (total_ - done) / rate : (done >= total_ ? 0 : -1);
        std::cout << "] " << pct << "%  " << human_size(done);
        if (total_ > 0) std::cout << "/" << human_size(total_);
        std::cout << "  " << human_rate(rate) << "  ETA " << human_time(eta) << "   " << std::flush;
    }

    void finish(int64_t done) {
        update(done);
        double elapsed = std::chrono::duration<double>(clock::now() - start_).count();
        double rate = elapsed > 0 ? done / elapsed : 0;
        std::cout << "\n  " << human_size(done) << " in " << human_time(elapsed)
                  << " (" << human_rate(rate) << ")\n";
    }

private:
    using clock = std::chrono::steady_clock;
    int64_t total_;
    clock::time_point start_;
    clock::time_point last_draw_ = clock::time_point{};
};

} // namespace ui
