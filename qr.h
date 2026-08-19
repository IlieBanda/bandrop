#pragma once
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

// A small, self-contained QR Code generator (byte mode, versions 1-10, all
// four error-correction levels). Enough to encode a URL for `bandrop serve`
// so a phone can scan it. No external dependencies; verified bit-for-bit
// against a reference encoder in the test suite.
namespace qr {

using Matrix = std::vector<std::vector<bool>>;
enum Ecl { L = 0, M = 1, Q = 2, H = 3 };

namespace detail {

// GF(256) tables, primitive polynomial 0x11d.
struct GF {
    std::array<int, 512> exp{};
    std::array<int, 256> log{};
    GF() {
        int x = 1;
        for (int i = 0; i < 255; ++i) {
            exp[i] = x; log[x] = i;
            x <<= 1;
            if (x & 0x100) x ^= 0x11d;
        }
        for (int i = 255; i < 512; ++i) exp[i] = exp[i - 255];
    }
    int mul(int a, int b) const { return (a == 0 || b == 0) ? 0 : exp[log[a] + log[b]]; }
};
inline const GF& gf() { static GF g; return g; }

// Reed-Solomon generator polynomial with `n` EC codewords.
inline std::vector<int> rs_gen(int n) {
    std::vector<int> g{1};
    for (int i = 0; i < n; ++i) {
        std::vector<int> ng(g.size() + 1, 0);
        for (size_t j = 0; j < g.size(); ++j) {
            ng[j] ^= g[j];
            ng[j + 1] ^= gf().mul(g[j], gf().exp[i]);
        }
        g = ng;
    }
    return g;
}

inline std::vector<int> rs_ec(const std::vector<int>& data, int n) {
    std::vector<int> gen = rs_gen(n);
    std::vector<int> res(data.size() + n, 0);
    for (size_t i = 0; i < data.size(); ++i) res[i] = data[i];
    for (size_t i = 0; i < data.size(); ++i) {
        int coef = res[i];
        if (coef == 0) continue;
        for (size_t j = 0; j < gen.size(); ++j)
            res[i + j] ^= gf().mul(gen[j], coef);
    }
    return std::vector<int>(res.end() - n, res.end());
}

// EC block layout per (version, ecl): {ec_per_block, g1_blocks, g1_data, g2_blocks, g2_data}.
struct Ecc { int ecpb, b1, d1, b2, d2; };
inline Ecc ecc_info(int v, int ecl) {
    static const Ecc T[10][4] = {
        /*1*/ {{7,1,19,0,0},{10,1,16,0,0},{13,1,13,0,0},{17,1,9,0,0}},
        /*2*/ {{10,1,34,0,0},{16,1,28,0,0},{22,1,22,0,0},{28,1,16,0,0}},
        /*3*/ {{15,1,55,0,0},{26,1,44,0,0},{18,2,17,0,0},{22,2,13,0,0}},
        /*4*/ {{20,1,80,0,0},{18,2,32,0,0},{26,2,24,0,0},{16,4,9,0,0}},
        /*5*/ {{26,1,108,0,0},{24,2,43,0,0},{18,2,15,2,16},{22,2,11,2,12}},
        /*6*/ {{18,2,68,0,0},{16,4,27,0,0},{24,4,19,0,0},{28,4,15,0,0}},
        /*7*/ {{20,2,78,0,0},{18,4,31,0,0},{18,2,14,4,15},{26,4,13,1,14}},
        /*8*/ {{24,2,97,0,0},{22,2,38,2,39},{22,4,18,2,19},{26,4,14,2,15}},
        /*9*/ {{30,2,116,0,0},{22,3,36,2,37},{20,4,16,4,17},{24,4,12,4,13}},
        /*10*/{{18,2,68,2,69},{26,4,43,1,44},{24,6,19,2,20},{28,6,15,2,16}},
    };
    return T[v - 1][ecl];
}

inline int data_capacity_bytes(int v, int ecl) {
    Ecc e = ecc_info(v, ecl);
    return e.b1 * e.d1 + e.b2 * e.d2;
}

// Alignment pattern center coordinates for versions 1-10.
inline std::vector<int> align_positions(int v) {
    static const std::vector<int> P[10] = {
        {}, {6,18}, {6,22}, {6,26}, {6,30}, {6,34}, {6,22,38}, {6,24,42}, {6,26,46}, {6,28,50}
    };
    return P[v - 1];
}

// 15-bit BCH format information (ecl+mask), already XOR-masked.
inline int format_bits(int ecl, int mask) {
    // Format's own 2-bit ECL field: M=00, L=01, H=10, Q=11.
    static const int ECL_FIELD[4] = {1, 0, 3, 2}; // index by our L,M,Q,H
    int data = (ECL_FIELD[ecl] << 3) | mask;
    int rem = data;
    for (int i = 0; i < 10; ++i) rem = (rem << 1) ^ (((rem >> 9) & 1) ? 0x537 : 0);
    int bits = ((data << 10) | rem) ^ 0x5412;
    return bits & 0x7fff;
}

// 18-bit BCH version information (versions 7+).
inline int version_bits(int v) {
    int rem = v;
    for (int i = 0; i < 12; ++i) rem = (rem << 1) ^ (((rem >> 11) & 1) ? 0x1f25 : 0);
    return (v << 12) | rem;
}

struct Grid {
    int n;
    std::vector<std::vector<int>> mod;   // -1 unset, 0/1 set
    std::vector<std::vector<bool>> fixed;
    explicit Grid(int size) : n(size),
        mod(size, std::vector<int>(size, -1)),
        fixed(size, std::vector<bool>(size, false)) {}
    void set(int r, int c, int v, bool fix) { mod[r][c] = v; fixed[r][c] = fix; }
};

inline void place_finder(Grid& g, int r, int c) {
    for (int dr = -1; dr <= 7; ++dr)
        for (int dc = -1; dc <= 7; ++dc) {
            int rr = r + dr, cc = c + dc;
            if (rr < 0 || cc < 0 || rr >= g.n || cc >= g.n) continue;
            bool dark = (dr >= 0 && dr <= 6 && (dc == 0 || dc == 6)) ||
                        (dc >= 0 && dc <= 6 && (dr == 0 || dr == 6)) ||
                        (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4);
            g.set(rr, cc, dark ? 1 : 0, true);
        }
}

inline void place_alignment(Grid& g, int cr, int cc) {
    for (int dr = -2; dr <= 2; ++dr)
        for (int dc = -2; dc <= 2; ++dc) {
            int m = std::max(std::abs(dr), std::abs(dc));
            g.set(cr + dr, cc + dc, (m != 1) ? 1 : 0, true);
        }
}

inline void build_function_patterns(Grid& g, int v) {
    int n = g.n;
    place_finder(g, 0, 0);
    place_finder(g, 0, n - 7);
    place_finder(g, n - 7, 0);
    // Timing patterns.
    for (int i = 8; i < n - 8; ++i) {
        if (g.mod[6][i] < 0) g.set(6, i, (i % 2 == 0) ? 1 : 0, true);
        if (g.mod[i][6] < 0) g.set(i, 6, (i % 2 == 0) ? 1 : 0, true);
    }
    // Alignment patterns (skip overlaps with finders).
    auto pos = align_positions(v);
    for (int a : pos) for (int b : pos) {
        if ((a == 6 && b == 6) || (a == 6 && b == n - 7) || (a == n - 7 && b == 6)) continue;
        place_alignment(g, a, b);
    }
    // Dark module.
    g.set(n - 8, 8, 1, true);
    // Reserve format areas (marked fixed; filled later).
    for (int i = 0; i < 9; ++i) {
        if (g.mod[8][i] < 0) g.set(8, i, 0, true);
        if (g.mod[i][8] < 0) g.set(i, 8, 0, true);
    }
    for (int i = 0; i < 8; ++i) {
        if (g.mod[8][n - 1 - i] < 0) g.set(8, n - 1 - i, 0, true);
        if (g.mod[n - 1 - i][8] < 0) g.set(n - 1 - i, 8, 0, true);
    }
    // Reserve version info areas (v>=7).
    if (v >= 7) {
        for (int i = 0; i < 6; ++i)
            for (int j = 0; j < 3; ++j) {
                g.set(i, n - 11 + j, 0, true);
                g.set(n - 11 + j, i, 0, true);
            }
    }
}

inline bool mask_bit(int mask, int r, int c) {
    switch (mask) {
        case 0: return (r + c) % 2 == 0;
        case 1: return r % 2 == 0;
        case 2: return c % 3 == 0;
        case 3: return (r + c) % 3 == 0;
        case 4: return (r / 2 + c / 3) % 2 == 0;
        case 5: return (r * c) % 2 + (r * c) % 3 == 0;
        case 6: return ((r * c) % 2 + (r * c) % 3) % 2 == 0;
        case 7: return ((r + c) % 2 + (r * c) % 3) % 2 == 0;
    }
    return false;
}

inline void place_data(Grid& g, const std::vector<int>& bits) {
    int n = g.n, idx = 0;
    for (int col = n - 1; col > 0; col -= 2) {
        if (col == 6) col = 5; // skip timing column
        for (int i = 0; i < n; ++i) {
            bool up = ((n - 1 - col) / 2) % 2 == 0; // effective column parity
            int row = up ? (n - 1 - i) : i;
            for (int k = 0; k < 2; ++k) {
                int c = col - k;
                if (g.mod[row][c] < 0) {
                    int bit = (idx < (int)bits.size()) ? bits[idx] : 0;
                    g.set(row, c, bit, false);
                    ++idx;
                }
            }
        }
    }
}

inline void apply_mask_and_format(Grid& g, int ecl, int mask, int v) {
    int n = g.n;
    for (int r = 0; r < n; ++r)
        for (int c = 0; c < n; ++c)
            if (!g.fixed[r][c] && mask_bit(mask, r, c))
                g.mod[r][c] ^= 1;

    int fmt = format_bits(ecl, mask);
    for (int b = 0; b < 15; ++b) {
        int bit = (fmt >> b) & 1;
        // First copy (around the top-left finder): bit 14 -> (8,0) ... bit 0 -> (0,8).
        int j = 14 - b;
        if (j < 6)       g.mod[8][j] = bit;
        else if (j == 6) g.mod[8][7] = bit;
        else if (j == 7) g.mod[8][8] = bit;
        else if (j == 8) g.mod[7][8] = bit;
        else             g.mod[14 - j][8] = bit;
        // Second copy (split across the other two finders).
        if (b < 8) g.mod[8][n - 1 - b] = bit;
        else       g.mod[n - 15 + b][8] = bit;
    }
    if (v >= 7) {
        int vb = version_bits(v);
        for (int i = 0; i < 18; ++i) {
            int bit = (vb >> i) & 1;
            int a = i / 3, b = i % 3;
            g.mod[a][n - 11 + b] = bit;
            g.mod[n - 11 + b][a] = bit;
        }
    }
}

inline int penalty(const Grid& g) {
    int n = g.n, score = 0;
    auto at = [&](int r, int c) { return g.mod[r][c] & 1; };
    // Rule 1: runs of 5+ same color.
    for (int r = 0; r < n; ++r) {
        int runc = 1, runr = 1;
        for (int c = 1; c < n; ++c) {
            runc = at(r, c) == at(r, c - 1) ? runc + 1 : 1;
            if (runc == 5) score += 3; else if (runc > 5) score += 1;
            runr = at(c, r) == at(c - 1, r) ? runr + 1 : 1;
            if (runr == 5) score += 3; else if (runr > 5) score += 1;
        }
    }
    // Rule 2: 2x2 blocks.
    for (int r = 0; r < n - 1; ++r)
        for (int c = 0; c < n - 1; ++c)
            if (at(r, c) == at(r, c + 1) && at(r, c) == at(r + 1, c) && at(r, c) == at(r + 1, c + 1))
                score += 3;
    // Rule 3: finder-like patterns 1:1:3:1:1 with 4 light.
    const int pat1[11] = {1,0,1,1,1,0,1,0,0,0,0};
    const int pat2[11] = {0,0,0,0,1,0,1,1,1,0,1};
    for (int r = 0; r < n; ++r)
        for (int c = 0; c <= n - 11; ++c) {
            bool m1 = true, m2 = true, n1 = true, n2 = true;
            for (int k = 0; k < 11; ++k) {
                if (at(r, c + k) != pat1[k]) m1 = false;
                if (at(r, c + k) != pat2[k]) m2 = false;
                if (at(c + k, r) != pat1[k]) n1 = false;
                if (at(c + k, r) != pat2[k]) n2 = false;
            }
            if (m1 || m2) score += 40;
            if (n1 || n2) score += 40;
        }
    // Rule 4: dark proportion.
    int dark = 0;
    for (int r = 0; r < n; ++r) for (int c = 0; c < n; ++c) dark += at(r, c);
    int pct = dark * 100 / (n * n);
    int k = std::abs(pct - 50) / 5;
    score += k * 10;
    return score;
}

} // namespace detail

// Encode with fixed parameters (for testing / exact control).
inline Matrix encode_fixed(const std::string& data, int version, int ecl, int mask) {
    using namespace detail;
    int n = 17 + 4 * version;

    // --- data bit stream ---
    std::vector<int> bits;
    auto push = [&](int val, int len) { for (int i = len - 1; i >= 0; --i) bits.push_back((val >> i) & 1); };
    push(0b0100, 4);                                   // byte mode
    int count_bits = (version <= 9) ? 8 : 16;
    push((int)data.size(), count_bits);
    for (unsigned char ch : data) push(ch, 8);

    int cap_bits = data_capacity_bytes(version, ecl) * 8;
    int term = std::min(4, cap_bits - (int)bits.size());
    push(0, term);
    while (bits.size() % 8) bits.push_back(0);
    for (int pad = 0xEC; (int)bits.size() < cap_bits; pad ^= (0xEC ^ 0x11))
        push(pad, 8);

    // --- split into blocks, compute EC, interleave ---
    std::vector<int> codewords;
    for (size_t i = 0; i < bits.size(); i += 8) {
        int b = 0; for (int k = 0; k < 8; ++k) b = (b << 1) | bits[i + k];
        codewords.push_back(b);
    }
    Ecc e = ecc_info(version, ecl);
    std::vector<std::vector<int>> dblocks, eblocks;
    int off = 0;
    auto add_blocks = [&](int count, int dlen) {
        for (int i = 0; i < count; ++i) {
            std::vector<int> d(codewords.begin() + off, codewords.begin() + off + dlen);
            off += dlen;
            dblocks.push_back(d);
            eblocks.push_back(rs_ec(d, e.ecpb));
        }
    };
    add_blocks(e.b1, e.d1);
    if (e.b2) add_blocks(e.b2, e.d2);

    std::vector<int> final_cw;
    int maxd = std::max(e.d1, e.d2);
    for (int i = 0; i < maxd; ++i)
        for (auto& blk : dblocks) if (i < (int)blk.size()) final_cw.push_back(blk[i]);
    for (int i = 0; i < e.ecpb; ++i)
        for (auto& blk : eblocks) final_cw.push_back(blk[i]);

    std::vector<int> final_bits;
    for (int cw : final_cw) for (int k = 7; k >= 0; --k) final_bits.push_back((cw >> k) & 1);

    // --- build the grid ---
    Grid g(n);
    build_function_patterns(g, version);
    place_data(g, final_bits);
    apply_mask_and_format(g, ecl, mask, version);

    Matrix out(n, std::vector<bool>(n, false));
    for (int r = 0; r < n; ++r) for (int c = 0; c < n; ++c) out[r][c] = (g.mod[r][c] & 1) != 0;
    return out;
}

// Encode, auto-selecting the smallest version (1-10) that fits and the best
// mask by the standard penalty score. Returns an empty matrix if it won't fit.
inline Matrix encode(const std::string& data, int ecl = M) {
    for (int v = 1; v <= 10; ++v) {
        int count_bits = (v <= 9) ? 8 : 16;
        int need = 4 + count_bits + 8 * (int)data.size();
        if (need <= detail::data_capacity_bytes(v, ecl) * 8) {
            int best = -1, best_score = 0;
            Matrix bestm;
            for (int mask = 0; mask < 8; ++mask) {
                Matrix m = encode_fixed(data, v, ecl, mask);
                detail::Grid tmp(m.size());
                for (size_t r = 0; r < m.size(); ++r) for (size_t c = 0; c < m.size(); ++c) tmp.mod[r][c] = m[r][c];
                int s = detail::penalty(tmp);
                if (best < 0 || s < best_score) { best = mask; best_score = s; bestm = m; }
            }
            return bestm;
        }
    }
    return {};
}

// Render a matrix as scannable ASCII using half-block characters (two rows per
// line). A quiet zone (border) is added so scanners lock on.
inline std::string to_ascii(const Matrix& m, int quiet = 2) {
    int n = (int)m.size();
    int N = n + 2 * quiet;
    auto dark = [&](int r, int c) -> bool {
        r -= quiet; c -= quiet;
        if (r < 0 || c < 0 || r >= n || c >= n) return false;
        return m[r][c];
    };
    std::string out;
    for (int r = 0; r < N; r += 2) {
        for (int c = 0; c < N; ++c) {
            bool top = dark(r, c);
            bool bot = (r + 1 < N) ? dark(r + 1, c) : false;
            // Dark module = black; use inverted half-blocks on a light bg.
            if (top && bot) out += " ";
            else if (top && !bot) out += "\xe2\x96\x84"; // lower half block
            else if (!top && bot) out += "\xe2\x96\x80"; // upper half block
            else out += "\xe2\x96\x88";                  // full block
        }
        out += "\n";
    }
    return out;
}

} // namespace qr
