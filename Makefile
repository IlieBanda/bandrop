# Convenience wrapper around the CMake build.
PREFIX ?= /usr/local
BUILD  ?= build

.PHONY: all build test install uninstall clean

all: build

build:
	cmake -S . -B $(BUILD) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD) --parallel

test: build
	ctest --test-dir $(BUILD) --output-on-failure

install: build
	cmake --install $(BUILD) --prefix $(PREFIX)

uninstall:
	rm -f $(PREFIX)/bin/bandrop

clean:
	rm -rf $(BUILD)
