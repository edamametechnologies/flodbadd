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
	@echo "Running Windows tests (Npcap DLL path configured automatically)..."
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

# -----------------------------------------------------------------------------
# macOS → Linux test helper (runs full Linux test-suite inside Docker)
# -----------------------------------------------------------------------------

# Image name to use/build
LINUX_TEST_IMAGE ?= edamame_linux_test

.PHONY: docker_build_linux_test linux_test_macos

# Build the test image (only needs to run when the Dockerfile changes)
docker_build_linux_test:
	docker build -t $(LINUX_TEST_IMAGE) -f Dockerfile.linux-test .

# Run the full Linux test-suite inside the container, mounting the current
# workspace so that the code being edited on macOS is tested.
#   $ make linux_test_macos
linux_test_macos: docker_build_linux_test
	@echo "NOTE: Docker Desktop on macOS has limited eBPF support due to the LinuxKit kernel."
	@echo "      eBPF tests may be skipped due to perf_event_open failures."
	@echo "      For full eBPF testing, use a native Linux environment or VM."
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

