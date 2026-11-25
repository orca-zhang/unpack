.PHONY: build sdk test check fixtures benchmark charts

build:
	cargo build --release --locked --bin unpack

sdk:
	python3 scripts/build_go_sdk.py

test: build sdk
	cargo test --locked --all-targets
	go test -race ./...

check: sdk
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets -- -D warnings
	go vet ./...
	python3 scripts/generate_charts.py --check
	python3 -m unittest discover -s scripts -p 'test_*.py'

fixtures:
	python3 scripts/generate_fixtures.py
	python3 scripts/generate_aplib_fixtures.py
	python3 scripts/generate_payload_fixtures.py
	python3 scripts/generate_version_fixtures.py

benchmark: sdk
	python3 scripts/benchmark.py

charts:
	cargo build --release --locked --bin unpack
	python3 scripts/generate_charts.py --engine target/release/unpack
