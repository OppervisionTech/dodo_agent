.PHONY: fmt lint test test-unit test-property test-integration test-security \
       test-security-static test-mutation test-coverage test-all \
       build-linux build-windows build-lite clean check \
       dist dist-linux-amd64 dist-linux-arm64 docker install

# Formatting
fmt:
	cargo fmt --all

# Linting
lint:
	cargo clippy --features linux -- -D warnings

# Run all tests
test:
	cargo test --features linux --all

## test-unit: Run only inline unit tests
test-unit:
	cargo test --features linux --lib --all

## test-property: Run property-based tests (proptest)
test-property:
	cargo test --features linux --all prop

## test-integration: Run integration tests
test-integration:
	cargo test --features linux --all --test '*'

## test-security: Run dynamic security tests
test-security:
	cargo test --features linux --all security

## test-security-static: Run static security analysis
test-security-static:
	bash scripts/security_audit.sh

## test-mutation: Run mutation tests (requires cargo-mutants)
test-mutation:
	bash scripts/mutation_test.sh

## test-coverage: Generate coverage report
test-coverage:
	bash scripts/check_coverage.sh

## test-all: Run all test types
test-all: test test-property test-integration test-security test-security-static

# Check compilation (all variants)
check:
	cargo check --features linux
	cargo check --features windows
	cargo check --features lite

# Build Linux variant (default)
build-linux:
	cargo build --release --features linux
	@echo "Built: target/release/aegis-agent"

# Build Windows variant
build-windows:
	cargo build --release --features windows --target x86_64-pc-windows-gnu
	@echo "Built: target/x86_64-pc-windows-gnu/release/aegis-agent.exe"

# Build Lite variant (IoT/Edge)
build-lite:
	cargo build --release --features lite
	@echo "Built: target/release/aegis-agent (lite)"

# Build static Linux binary with musl
build-static:
	cargo build --release --features linux --target x86_64-unknown-linux-musl
	@echo "Built: target/x86_64-unknown-linux-musl/release/aegis-agent"

# Build for ARM (cross-compilation)
build-arm:
	cross build --release --features lite --target aarch64-unknown-linux-musl
	@echo "Built: target/aarch64-unknown-linux-musl/release/aegis-agent"

# Clean build artifacts
clean:
	cargo clean

# Run with default config (dev mode)
run:
	AEGIS_CONFIG=config/agent.yaml RUST_LOG=debug cargo run --features linux

# Generate checksums for release binaries
checksums:
	@cd target/release && sha256sum aegis-agent > aegis-agent.sha256 2>/dev/null || true
	@echo "Checksums generated"

# Cross-compile all release targets via build.sh
dist:
	./scripts/build.sh all

# Cross-compile individual targets
dist-linux-amd64:
	./scripts/build.sh linux-amd64

dist-linux-arm64:
	USE_CROSS=1 ./scripts/build.sh linux-arm64

# Docker build
docker:
	docker build -t aegis-agent:latest .

docker-lite:
	docker build --build-arg VARIANT=lite -t aegis-agent-lite:latest .

# Install locally (requires root)
install:
	sudo ./scripts/install.sh
