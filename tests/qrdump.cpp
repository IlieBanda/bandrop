#include <cstdio>
#include <cstdlib>
#include <string>
#include "../qr.h"
int main(int argc, char** argv) {
    // args: data version ecl mask
    std::string data = argv[1];
    int v = atoi(argv[2]), ecl = atoi(argv[3]), mask = atoi(argv[4]);
    auto m = qr::encode_fixed(data, v, ecl, mask);
    for (auto& row : m) { for (bool b : row) putchar(b ? '1' : '0'); putchar('\n'); }
    return 0;
}
