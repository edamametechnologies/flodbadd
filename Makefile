.PHONY: upgrade unused_dependencies format clean test ios android ebpf_setup

upgrade:
	rustup update
	cargo install -f cargo-upgrades
	cargo upgrades
	cargo update

unused_dependencies:
	cargo +nightly udeps

format:
	cargo fmt
	cd ebpf && cargo fmt

clean:
	cargo clean
	rm -rf ./build/
	rm -rf ./target/

check:
	cargo hack check --all-features --all-targets
	cargo hack check --all-features --all-targets --target=aarch64-apple-ios
	cargo hack check --all-features --all-targets --target=aarch64-unknown-linux-gnu

ios:
	cargo build --target=aarch64-apple-ios

android:
	cross build --release --target x86_64-linux-android


windows_test:
	cargo test --features packetcapture,asyncpacketcapture -- --nocapture --test-threads=1

unix_test:
	cargo test -- --nocapture
	# Use sudo for capture tests - on Linux need to pass cargo path
	$(shell which sudo) -E $(shell which cargo) test --features packetcapture,asyncpacketcapture -- --nocapture --test-threads=1
	$(shell which sudo) -E $(shell which cargo) test --features packetcapture -- --nocapture --test-threads=1

# Setup the environment for eBPF testing
ebpf_setup:
	@echo "Setting up eBPF environment..."
	-sudo mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
	-sudo mount -t bpf none /sys/fs/bpf 2>/dev/null || true
	-sudo sysctl -w kernel.perf_event_paranoid=-1 || true
	-sudo sysctl -w kernel.unprivileged_bpf_disabled=0 || true
	-sudo sysctl -w net.core.bpf_jit_enable=1 || true

linux_test_ebpf: ebpf_setup
	@echo "Running eBPF tests with configured environment..."
	@echo "Current kernel: $$(uname -r)"
	@echo "Debug filesystem: $$(mount | grep debugfs || echo 'Not mounted')"
	@echo "BPF filesystem: $$(mount | grep bpf || echo 'Not mounted')"
	@echo "perf_event_paranoid = $$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 'Not available')"
	@echo "unprivileged_bpf_disabled = $$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 'Not available')"
	$(shell which sudo) -E $(shell which cargo) test --features packetcapture,asyncpacketcapture,ebpf -- --nocapture --test-threads=1

linux_test: unix_test linux_test_ebpf

linux_test_no_ebpf: unix_test

macos_test: unix_test

ios_test: ios

android_test: android

# Anomaly detection tests - run the security anomaly detection tests
anomaly_test:
	echo "Running anomaly detection tests"
	$(shell which cargo) test --features packetcapture,asyncpacketcapture --test anomaly_test -- --nocapture

metrics_test:
	echo "Running metrics tests"
	$(shell which cargo) test --features packetcapture,asyncpacketcapture --test metrics_test -- --nocapture

# Include anomaly tests in macOS test suite - use the macOS-specific version
macos_test_all: macos_test anomaly_test metrics_test

# Include anomaly tests in Linux test suite with eBPF
linux_test_all: linux_test anomaly_test metrics_test

# =============================================================================
# macOS → Linux test helpers
# =============================================================================
# Two options for running Linux tests from macOS:
#   1. Docker (quick, but limited eBPF support due to LinuxKit kernel)
#   2. Lima VM (full eBPF support with real Linux kernel)
# =============================================================================

# -----------------------------------------------------------------------------
# Option 1: Docker (limited eBPF - LinuxKit kernel doesn't support kprobes well)
# -----------------------------------------------------------------------------

LINUX_TEST_IMAGE ?= edamame_linux_test

.PHONY: docker_build_linux_test docker_linux_test

# Build the Docker test image
docker_build_linux_test:
	docker build -t $(LINUX_TEST_IMAGE) -f Dockerfile.linux-test .

# Run tests in Docker (eBPF tests will likely be skipped)
docker_linux_test: docker_build_linux_test
	@echo "============================================================"
	@echo "NOTE: Docker Desktop on macOS has limited eBPF support."
	@echo "      eBPF kprobe tests will likely be skipped."
	@echo "      For full eBPF testing, use: make lima_test"
	@echo "============================================================"
	@echo ""
	docker run --rm -i \
		--privileged \
		--cap-add=SYS_ADMIN \
		--cap-add=SYS_PTRACE \
		--security-opt seccomp=unconfined \
		-v $(CURDIR):/workspace \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v /sys/fs/bpf:/sys/fs/bpf \
		-w /workspace \
		$(LINUX_TEST_IMAGE) make linux_test

# Alias for backwards compatibility
linux_test_macos: docker_linux_test

# -----------------------------------------------------------------------------
# Option 2: Lima VM (full eBPF support - recommended for eBPF testing)
# -----------------------------------------------------------------------------

LIMA_VM_NAME ?= ebpf-test
LIMA_CONFIG  ?= Lima.linux-test.yml

.PHONY: lima_create lima_start lima_stop lima_delete lima_shell lima_test lima_status

# Check if Lima is installed
lima_check:
	@which limactl > /dev/null || (echo "Lima not installed. Install with: brew install lima" && exit 1)

# Create the Lima VM (only needs to be done once)
lima_create: lima_check
	@echo "Creating Lima VM '$(LIMA_VM_NAME)'..."
	@echo "This may take a few minutes on first run (downloading Ubuntu image)..."
	limactl create --name=$(LIMA_VM_NAME) $(LIMA_CONFIG)
	@echo ""
	@echo "VM created. Start it with: make lima_start"

# Start the Lima VM
lima_start: lima_check
	@if limactl list -q | grep -q "^$(LIMA_VM_NAME)$$"; then \
		echo "Starting Lima VM '$(LIMA_VM_NAME)'..."; \
		limactl start $(LIMA_VM_NAME); \
	else \
		echo "VM '$(LIMA_VM_NAME)' doesn't exist. Creating it first..."; \
		$(MAKE) lima_create; \
		limactl start $(LIMA_VM_NAME); \
	fi

# Stop the Lima VM
lima_stop: lima_check
	@echo "Stopping Lima VM '$(LIMA_VM_NAME)'..."
	-limactl stop $(LIMA_VM_NAME)

# Delete the Lima VM
lima_delete: lima_check
	@echo "Deleting Lima VM '$(LIMA_VM_NAME)'..."
	-limactl delete $(LIMA_VM_NAME)

# Open a shell in the Lima VM
lima_shell: lima_start
	limactl shell $(LIMA_VM_NAME)

# Show Lima VM status
lima_status: lima_check
	@echo "Lima VM status:"
	@limactl list
	@echo ""
	@if limactl list -q | grep -q "^$(LIMA_VM_NAME)$$"; then \
		echo "VM '$(LIMA_VM_NAME)' details:"; \
		limactl info $(LIMA_VM_NAME) 2>/dev/null || true; \
	fi

# Run Linux tests inside the Lima VM (recommended for eBPF testing)
lima_test: lima_start
	@echo "============================================================"
	@echo "Running Linux tests in Lima VM '$(LIMA_VM_NAME)'..."
	@echo "This provides full eBPF support with a real Linux kernel."
	@echo "============================================================"
	@echo ""
	limactl shell $(LIMA_VM_NAME) -- bash -c '\
		cd /Users/flyonnet/Programming/flodbadd && \
		source $$HOME/.cargo/env && \
		echo "=== Environment ===" && \
		echo "Kernel: $$(uname -r)" && \
		echo "Clang: $$(clang --version | head -1)" && \
		echo "Rust: $$(rustc --version)" && \
		echo "perf_event_paranoid: $$(cat /proc/sys/kernel/perf_event_paranoid)" && \
		echo "" && \
		sudo -E RUSTUP_HOME=$$HOME/.rustup CARGO_HOME=$$HOME/.cargo \
			$$HOME/.cargo/bin/cargo test --features packetcapture,asyncpacketcapture,ebpf -- --nocapture --test-threads=1 \
	'

# Quick eBPF-only test in Lima (skips non-eBPF tests)
lima_test_ebpf: lima_start
	@echo "Running eBPF-specific tests in Lima VM..."
	limactl shell $(LIMA_VM_NAME) -- bash -c '\
		cd /Users/flyonnet/Programming/flodbadd && \
		source $$HOME/.cargo/env && \
		sudo -E RUSTUP_HOME=$$HOME/.rustup CARGO_HOME=$$HOME/.cargo \
			$$HOME/.cargo/bin/cargo test --features packetcapture,asyncpacketcapture,ebpf test_ebpf -- --nocapture \
	'

# -----------------------------------------------------------------------------
# Option 3: Alpine Linux VM (test eBPF on musl libc)
# -----------------------------------------------------------------------------

ALPINE_VM_NAME ?= alpine-test
ALPINE_CONFIG  ?= Lima.alpine-test.yml

.PHONY: alpine_create alpine_start alpine_stop alpine_delete alpine_shell alpine_test alpine_status

# Create the Alpine VM
alpine_create: lima_check
	@echo "Creating Alpine Linux VM '$(ALPINE_VM_NAME)'..."
	limactl create --name=$(ALPINE_VM_NAME) $(ALPINE_CONFIG)
	@echo ""
	@echo "Alpine VM created. Start it with: make alpine_start"

# Start the Alpine VM
alpine_start: lima_check
	@if limactl list -q | grep -q "^$(ALPINE_VM_NAME)$$"; then \
		echo "Starting Alpine VM '$(ALPINE_VM_NAME)'..."; \
		limactl start $(ALPINE_VM_NAME); \
	else \
		echo "Alpine VM '$(ALPINE_VM_NAME)' doesn't exist. Creating it first..."; \
		$(MAKE) alpine_create; \
		limactl start $(ALPINE_VM_NAME); \
	fi

# Stop the Alpine VM
alpine_stop: lima_check
	@echo "Stopping Alpine VM '$(ALPINE_VM_NAME)'..."
	-limactl stop $(ALPINE_VM_NAME)

# Delete the Alpine VM
alpine_delete: lima_check
	@echo "Deleting Alpine VM '$(ALPINE_VM_NAME)'..."
	-limactl delete $(ALPINE_VM_NAME)

# Open a shell in the Alpine VM
alpine_shell: alpine_start
	limactl shell $(ALPINE_VM_NAME)

# Show Alpine VM status
alpine_status: lima_check
	@echo "Alpine VM status:"
	@limactl list | grep -E "NAME|$(ALPINE_VM_NAME)" || echo "Alpine VM not created"

# Run eBPF tests in Alpine VM
alpine_test: alpine_start
	@echo "============================================================"
	@echo "Running eBPF tests in Alpine Linux VM '$(ALPINE_VM_NAME)'..."
	@echo "Testing eBPF with musl libc (Alpine uses musl, not glibc)"
	@echo "============================================================"
	@echo ""
	limactl shell $(ALPINE_VM_NAME) -- bash -c '\
		cd /Users/flyonnet/Programming/flodbadd && \
		source $$HOME/.cargo/env && \
		echo "=== Alpine Environment ===" && \
		echo "Kernel: $$(uname -r)" && \
		echo "Clang: $$(clang --version | head -1)" && \
		echo "Rust: $$(rustc --version)" && \
		echo "libc: musl (Alpine)" && \
		echo "perf_event_paranoid: $$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo N/A)" && \
		echo "" && \
		sudo -E RUSTUP_HOME=$$HOME/.rustup CARGO_HOME=$$HOME/.cargo \
			$$HOME/.cargo/bin/cargo test --features packetcapture,asyncpacketcapture,ebpf test_ebpf -- --nocapture \
	'

# -----------------------------------------------------------------------------
# Option 4: Ubuntu 22.04 LTS (older glibc, common in production)
# -----------------------------------------------------------------------------

UBUNTU2204_VM_NAME ?= ubuntu2204-test
UBUNTU2204_CONFIG  ?= Lima.ubuntu2204-test.yml

.PHONY: ubuntu2204_create ubuntu2204_start ubuntu2204_stop ubuntu2204_delete ubuntu2204_test

ubuntu2204_create: lima_check
	@echo "Creating Ubuntu 22.04 VM '$(UBUNTU2204_VM_NAME)'..."
	limactl create --name=$(UBUNTU2204_VM_NAME) $(UBUNTU2204_CONFIG)

ubuntu2204_start: lima_check
	@if limactl list -q | grep -q "^$(UBUNTU2204_VM_NAME)$$"; then \
		limactl start $(UBUNTU2204_VM_NAME); \
	else \
		$(MAKE) ubuntu2204_create; \
		limactl start $(UBUNTU2204_VM_NAME); \
	fi

ubuntu2204_stop: lima_check
	-limactl stop $(UBUNTU2204_VM_NAME)

ubuntu2204_delete: lima_check
	-limactl delete $(UBUNTU2204_VM_NAME)

ubuntu2204_test: ubuntu2204_start
	@echo "Running eBPF tests on Ubuntu 22.04 LTS..."
	limactl shell $(UBUNTU2204_VM_NAME) -- bash -c '\
		cd /Users/flyonnet/Programming/flodbadd && \
		source $$HOME/.cargo/env && \
		echo "=== Ubuntu 22.04 Environment ===" && \
		echo "Kernel: $$(uname -r)" && \
		cat /etc/lsb-release | grep DESCRIPTION && \
		sudo -E RUSTUP_HOME=$$HOME/.rustup CARGO_HOME=$$HOME/.cargo \
			$$HOME/.cargo/bin/cargo test --features packetcapture,asyncpacketcapture,ebpf test_ebpf_availability -- --nocapture \
	'

# -----------------------------------------------------------------------------
# Option 5: Alpine 3.18 (older musl, stability testing)
# Note: Alpine 3.15 cloud images are no longer available
# -----------------------------------------------------------------------------

ALPINE318_VM_NAME ?= alpine318-test
ALPINE318_CONFIG  ?= Lima.alpine315-test.yml

.PHONY: alpine318_create alpine318_start alpine318_stop alpine318_delete alpine318_test

alpine318_create: lima_check
	@echo "Creating Alpine 3.18 VM '$(ALPINE318_VM_NAME)'..."
	limactl create --name=$(ALPINE318_VM_NAME) $(ALPINE318_CONFIG)

alpine318_start: lima_check
	@if limactl list -q | grep -q "^$(ALPINE318_VM_NAME)$$"; then \
		limactl start $(ALPINE318_VM_NAME); \
	else \
		$(MAKE) alpine318_create; \
		limactl start $(ALPINE318_VM_NAME); \
	fi

alpine318_stop: lima_check
	-limactl stop $(ALPINE318_VM_NAME)

alpine318_delete: lima_check
	-limactl delete $(ALPINE318_VM_NAME)

alpine318_test: alpine318_start
	@echo "Running eBPF tests on Alpine 3.18..."
	limactl shell $(ALPINE318_VM_NAME) -- sh -c '\
		cd /Users/flyonnet/Programming/flodbadd && \
		. $$HOME/.cargo/env && \
		echo "=== Alpine 3.18 Environment ===" && \
		echo "Kernel: $$(uname -r)" && \
		cat /etc/alpine-release && \
		sudo -E RUSTUP_HOME=$$HOME/.rustup CARGO_HOME=$$HOME/.cargo \
			$$HOME/.cargo/bin/cargo test --features packetcapture,asyncpacketcapture,ebpf test_ebpf_availability -- --nocapture \
	'

# Alias for backwards compatibility
alpine315_test: alpine318_test

# -----------------------------------------------------------------------------
# Option 6: Ubuntu 20.04 LTS (oldest supported, kernel 5.4)
# -----------------------------------------------------------------------------

UBUNTU2004_VM_NAME ?= ubuntu2004-test
UBUNTU2004_CONFIG  ?= Lima.ubuntu2004-test.yml

.PHONY: ubuntu2004_create ubuntu2004_start ubuntu2004_stop ubuntu2004_delete ubuntu2004_test

ubuntu2004_create: lima_check
	@echo "Creating Ubuntu 20.04 VM '$(UBUNTU2004_VM_NAME)'..."
	limactl create --name=$(UBUNTU2004_VM_NAME) $(UBUNTU2004_CONFIG)

ubuntu2004_start: lima_check
	@if limactl list -q | grep -q "^$(UBUNTU2004_VM_NAME)$$"; then \
		limactl start $(UBUNTU2004_VM_NAME); \
	else \
		$(MAKE) ubuntu2004_create; \
		limactl start $(UBUNTU2004_VM_NAME); \
	fi

ubuntu2004_stop: lima_check
	-limactl stop $(UBUNTU2004_VM_NAME)

ubuntu2004_delete: lima_check
	-limactl delete $(UBUNTU2004_VM_NAME)

ubuntu2004_test: ubuntu2004_start
	@echo "Running eBPF tests on Ubuntu 20.04 LTS (kernel 5.4)..."
	limactl shell $(UBUNTU2004_VM_NAME) -- bash -c '\
		cd /Users/flyonnet/Programming/flodbadd && \
		source $$HOME/.cargo/env && \
		echo "=== Ubuntu 20.04 Environment ===" && \
		echo "Kernel: $$(uname -r)" && \
		cat /etc/lsb-release | grep DESCRIPTION && \
		sudo -E RUSTUP_HOME=$$HOME/.rustup CARGO_HOME=$$HOME/.cargo \
			$$HOME/.cargo/bin/cargo test --features packetcapture,asyncpacketcapture,ebpf test_ebpf_availability -- --nocapture \
	'

# =============================================================================
# Test all distributions
# =============================================================================

.PHONY: test_all_distros stop_all_vms

test_all_distros:
	@echo "Testing eBPF on all supported distributions..."
	@echo ""
	@echo "=== Ubuntu 24.04 (latest) ===" && $(MAKE) lima_test_ebpf && echo "✅ PASSED" || echo "❌ FAILED"
	@echo "=== Ubuntu 22.04 LTS ===" && $(MAKE) ubuntu2204_test && echo "✅ PASSED" || echo "❌ FAILED"
	@echo "=== Ubuntu 20.04 LTS ===" && $(MAKE) ubuntu2004_test && echo "✅ PASSED" || echo "❌ FAILED"
	@echo "=== Alpine 3.20 (latest) ===" && $(MAKE) alpine_test && echo "✅ PASSED" || echo "❌ FAILED"
	@echo "=== Alpine 3.18 ===" && $(MAKE) alpine318_test && echo "✅ PASSED" || echo "❌ FAILED"
	@echo ""
	@echo "All distribution tests complete!"

stop_all_vms:
	@echo "Stopping all Lima VMs..."
	-limactl stop ebpf-test
	-limactl stop ubuntu2204-test
	-limactl stop ubuntu2004-test
	-limactl stop alpine-test
	-limactl stop alpine318-test
	@echo "All VMs stopped."

# =============================================================================
# Recommended workflow for macOS developers:
# =============================================================================
#
# First time setup:
#   1. Install Lima: brew install lima
#   2. Create VMs:   make lima_create        (Ubuntu 24.04 - recommended)
#                    make ubuntu2204_create  (Ubuntu 22.04 LTS)
#                    make ubuntu2004_create  (Ubuntu 20.04 LTS)
#                    make alpine_create      (Alpine 3.20)
#                    make alpine318_create   (Alpine 3.18)
#
# Running tests:
#   - Ubuntu 24.04:  make lima_test_ebpf     (recommended - latest)
#   - Ubuntu 22.04:  make ubuntu2204_test    (LTS production)
#   - Ubuntu 20.04:  make ubuntu2004_test    (older LTS)
#   - Alpine 3.20:   make alpine_test        (latest musl)
#   - Alpine 3.18:   make alpine318_test     (older musl)
#   - All distros:   make test_all_distros   (test everything)
#
# VM management:
#   - List all:      limactl list
#   - Stop all:      make stop_all_vms
# =============================================================================
