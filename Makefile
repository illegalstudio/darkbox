PYTHON ?= python3

.PHONY: build test check package release

build:
	cargo build --release --locked

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'
	cargo test --all-targets --locked

check:
	$(PYTHON) scripts/bundle_catalog.py --check
	cargo fmt --all -- --check
	cargo clippy --all-targets --locked -- -D warnings
	$(MAKE) test

package: build
	$(PYTHON) scripts/package.py --target "$$(rustc -vV | sed -n 's/^host: //p')"

# Propose a software version, prepare it, then confirm the commit, tag and push.
release:
	$(PYTHON) scripts/release.py $(ARGS)
