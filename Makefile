.PHONY: build test check fixtures benchmark charts

build:
	cargo build --locked
	go build -o bin/unpack ./cmd/unpack

test: build
	cargo test --locked --all-targets
	go test -race ./...

check:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets -- -D warnings
	go vet ./...
	python3 scripts/generate_charts.py --check

fixtures:
	python3 scripts/generate_fixtures.py
	python3 scripts/generate_aplib_fixtures.py
	python3 scripts/generate_payload_fixtures.py

benchmark:
	python3 scripts/benchmark.py

charts:
	cargo build --release --locked
	python3 scripts/generate_charts.py --engine target/release/unpack-rs
