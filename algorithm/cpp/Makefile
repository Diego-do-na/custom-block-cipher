# Build for the C++ cipher: native library + CLI + Catch2 tests (clang++/g++), and the
# WebAssembly module the demo and the TypeScript bindings load (Emscripten's em++).
#
#   make test    build and run the native test suite
#   make cli     build the native CLI (build/cipher-cli)
#   make wasm    build ../wasm/generated/cipher.mjs (single file, .wasm embedded)
#   make clean

CXX ?= clang++
EMXX ?= em++
TESTED_EMSCRIPTEN_VERSION := 6.0.10

BUILD := build
WASM_OUT := ../wasm/generated/cipher.mjs
GOLDEN := $(abspath ../test/vectors/golden.json)

CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -Wpedantic -Iinclude
TEST_CXXFLAGS := -std=c++20 -O1 -Iinclude -Ithird_party -DGOLDEN_VECTORS_PATH='"$(GOLDEN)"'

SRCS := $(wildcard src/*.cpp)
HDRS := $(wildcard include/cipher/*.hpp)
OBJS := $(SRCS:src/%.cpp=$(BUILD)/obj/%.o)
TESTS := $(wildcard test/*.cpp)
TEST_OBJS := $(TESTS:test/%.cpp=$(BUILD)/test/%.o)
CATCH_OBJ := $(BUILD)/third_party/catch_amalgamated.o

EMXXFLAGS := -std=c++20 -O2 -Iinclude -fexceptions -lembind \
	-sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createCipherModule \
	-sSINGLE_FILE=1 -sENVIRONMENT=web,node -sALLOW_MEMORY_GROWTH=1

.PHONY: all native cli test wasm clean
all: native

native: $(BUILD)/libcipher.a cli

cli: $(BUILD)/cipher-cli

test: $(BUILD)/cipher-tests
	./$(BUILD)/cipher-tests

$(BUILD)/obj/%.o: src/%.cpp $(HDRS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/libcipher.a: $(OBJS)
	ar rcs $@ $^

$(BUILD)/cipher-cli: cli/main.cpp $(BUILD)/libcipher.a
	$(CXX) $(CXXFLAGS) $< $(BUILD)/libcipher.a -o $@

# Catch2's amalgamated source is large and never changes, so it's compiled once and cached.
$(CATCH_OBJ): third_party/catch2/catch_amalgamated.cpp third_party/catch2/catch_amalgamated.hpp
	@mkdir -p $(dir $@)
	$(CXX) -std=c++20 -O1 -Ithird_party/catch2 -c $< -o $@

$(BUILD)/test/%.o: test/%.cpp $(HDRS)
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) -c $< -o $@

$(BUILD)/cipher-tests: $(TEST_OBJS) $(CATCH_OBJ) $(BUILD)/libcipher.a
	$(CXX) $^ -o $@

wasm: $(WASM_OUT)

$(WASM_OUT): $(SRCS) $(HDRS) wasm/bindings.cpp
	@command -v $(EMXX) >/dev/null || { echo "error: $(EMXX) not found. Install Emscripten $(TESTED_EMSCRIPTEN_VERSION) (brew install emscripten)." >&2; exit 1; }
	@version=$$($(EMXX) --version 2>/dev/null | head -1 | sed -E 's/.* ([0-9]+\.[0-9]+\.[0-9]+).*/\1/'); \
	  [ "$$version" = "$(TESTED_EMSCRIPTEN_VERSION)" ] || \
	  echo "warning: building with Emscripten $$version; this project is tested with $(TESTED_EMSCRIPTEN_VERSION)." >&2
	@mkdir -p $(dir $@)
	$(EMXX) $(EMXXFLAGS) $(SRCS) wasm/bindings.cpp -o $@

clean:
	rm -rf $(BUILD) $(WASM_OUT)
