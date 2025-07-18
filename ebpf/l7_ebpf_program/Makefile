# Makefile for building eBPF L7 program
# This compiles the C code into an eBPF object file that can be loaded by the Rust application

# Default target
.PHONY: all clean install

# Build configuration
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Source and output files
SRC_DIR := src
BUILD_DIR := ../../../target/ebpf
OBJ_FILE := $(BUILD_DIR)/l7_ebpf.o
SRC_FILE := $(SRC_DIR)/l7_ebpf.c

# Compiler flags for eBPF
CFLAGS := -target bpf \
	-D__BPF_TRACING__ \
	-Wall \
	-Wextra \
	-Werror \
	-O2 \
	-g \
	-c

# Include directories (adjust paths as needed)
INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu \
	-I/usr/include/bpf \
	-I./include

# Default target
all: $(OBJ_FILE)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile the eBPF program
$(OBJ_FILE): $(SRC_FILE) | $(BUILD_DIR)
	@echo "Building eBPF program: $@"
	$(CLANG) $(CFLAGS) $(INCLUDES) -o $@ $<
	$(LLVM_STRIP) -g $@
	@echo "eBPF program built successfully: $@"

# Clean build artifacts
clean:
	rm -f $(OBJ_FILE)
	@echo "Cleaned build artifacts"

# Install to system location (optional)
install: $(OBJ_FILE)
	@echo "Installing eBPF program to system..."
	sudo mkdir -p /usr/local/lib/ebpf
	sudo cp $(OBJ_FILE) /usr/local/lib/ebpf/
	@echo "eBPF program installed to /usr/local/lib/ebpf/"

# Development targets
.PHONY: debug check deps

# Debug build with verbose output
debug:
	@echo "Building debug version..."
	$(CLANG) $(CFLAGS) $(INCLUDES) -DDEBUG -o $(OBJ_FILE) $(SRC_FILE)
	$(LLVM_STRIP) -g $(OBJ_FILE)

# Check for required tools
check:
	@echo "Checking for required tools..."
	@which $(CLANG) > /dev/null || (echo "Error: clang not found" && exit 1)
	@which $(LLVM_STRIP) > /dev/null || (echo "Error: llvm-strip not found" && exit 1)
	@echo "All required tools found"

# Install build dependencies (Ubuntu/Debian)
deps:
	@echo "Installing build dependencies..."
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(shell uname -r)
	@echo "Dependencies installed"

# Show build info
info:
	@echo "Build Information:"
	@echo "  Architecture: $(ARCH)"
	@echo "  Clang: $(CLANG)"
	@echo "  LLVM Strip: $(LLVM_STRIP)"
	@echo "  Source: $(SRC_FILE)"
	@echo "  Output: $(OBJ_FILE)"
	@echo "  Includes: $(INCLUDES)" 