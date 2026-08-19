#pragma once
#include <sys/stat.h>
#include <dirent.h>
#include <algorithm>
#include <string>
#include <vector>

// Enumerate files to send. A single file yields one entry; a directory is
// walked recursively, preserving relative paths under the directory's name.
namespace archive {

struct Entry {
    std::string abs_path;  // path to read on disk
    std::string rel_path;  // path stored/recreated on the receiver
    int64_t size;
};

inline bool is_dir(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

inline bool is_reg(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

inline int64_t file_size(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 ? (int64_t)st.st_size : -1;
}

inline std::string basename_of(std::string p) {
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    size_t s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

inline void walk(const std::string& abs, const std::string& rel, std::vector<Entry>& out) {
    if (is_reg(abs)) {
        out.push_back({abs, rel, file_size(abs)});
        return;
    }
    if (!is_dir(abs)) return;
    DIR* d = ::opendir(abs.c_str());
    if (!d) return;
    std::vector<std::string> names;
    for (dirent* e; (e = ::readdir(d)) != nullptr; ) {
        std::string n = e->d_name;
        if (n == "." || n == "..") continue;
        names.push_back(n);
    }
    ::closedir(d);
    std::sort(names.begin(), names.end());
    for (const auto& n : names)
        walk(abs + "/" + n, rel + "/" + n, out);
}

// Build the list of entries for a set of input paths.
inline std::vector<Entry> collect(const std::vector<std::string>& inputs) {
    std::vector<Entry> out;
    for (const auto& in : inputs) {
        std::string top = basename_of(in);
        walk(in, top, out);
    }
    return out;
}

// Create parent directories for a relative path under `base` (mkdir -p).
inline bool make_parent_dirs(const std::string& base, const std::string& rel) {
    std::string path = base;
    size_t start = 0;
    for (size_t i = 0; i < rel.size(); ++i) {
        if (rel[i] == '/') {
            path += "/" + rel.substr(start, i - start);
            ::mkdir(path.c_str(), 0755);
            start = i + 1;
        }
    }
    return true;
}

} // namespace archive
