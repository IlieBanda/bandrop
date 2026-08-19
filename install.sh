#!/usr/bin/env sh
# Bandrop one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/IlieBanda/bandrop/main/install.sh | sh
#
# Detects your OS, ensures build dependencies (OpenSSL, zlib, CMake, a C++
# compiler), builds Bandrop from source, and installs the `bandrop` binary.
# Override the install location with PREFIX=/path (default: /usr/local).
set -eu

REPO="${BANDROP_REPO:-https://github.com/IlieBanda/bandrop.git}"
REF="${BANDROP_REF:-main}"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$1" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if have sudo; then SUDO="sudo"; fi
fi

install_deps() {
    OS="$(uname -s)"
    case "$OS" in
        Darwin)
            if ! have brew; then
                warn "Homebrew not found; assuming build tools are already present."
                return
            fi
            say "Installing dependencies via Homebrew..."
            brew install cmake openssl@3 zlib >/dev/null || warn "brew install reported an issue; continuing."
            ;;
        Linux)
            if have apt-get; then
                say "Installing dependencies via apt..."
                $SUDO apt-get update -qq && $SUDO apt-get install -y -qq cmake g++ libssl-dev zlib1g-dev
            elif have dnf; then
                say "Installing dependencies via dnf..."
                $SUDO dnf install -y -q cmake gcc-c++ openssl-devel zlib-devel
            elif have pacman; then
                say "Installing dependencies via pacman..."
                $SUDO pacman -Sy --noconfirm --needed cmake gcc openssl zlib
            elif have apk; then
                say "Installing dependencies via apk..."
                $SUDO apk add --no-cache cmake g++ make openssl-dev zlib-dev
            else
                warn "Unknown package manager; ensure cmake, a C++ compiler, OpenSSL and zlib dev headers are installed."
            fi
            ;;
        *) warn "Unrecognized OS '$OS'; attempting to build anyway." ;;
    esac
}

main() {
    have cmake || install_deps
    have cmake || install_deps   # a second pass if the first bootstrapped the pkg manager
    have git   || die "git is required to fetch the source."

    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    say "Fetching Bandrop ($REF)..."
    git clone --depth 1 --branch "$REF" "$REPO" "$TMP/src" 2>/dev/null \
        || git clone --depth 1 "$REPO" "$TMP/src"

    say "Building..."
    cmake -S "$TMP/src" -B "$TMP/build" -DCMAKE_BUILD_TYPE=Release >/dev/null
    cmake --build "$TMP/build" --parallel >/dev/null

    say "Installing to $BINDIR (may prompt for your password)..."
    $SUDO cmake --install "$TMP/build" --prefix "$PREFIX" >/dev/null \
        || { $SUDO mkdir -p "$BINDIR"; $SUDO cp "$TMP/build/bandrop" "$BINDIR/bandrop"; }

    say "Installed: $("$BINDIR/bandrop" --version 2>/dev/null || echo bandrop)"
    say "Try:  bandrop --help"
}

main "$@"
