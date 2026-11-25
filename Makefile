PYTHON ?= python3

.PHONY: build test check package release

build:
	cargo build --release --locked

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'
	cargo test --all-targets --locked
	cargo test --all-targets --no-default-features --locked
	# Sync tests default to the newest protocol; repeat them on the one bound to common 1.5.0.
	DARKBOX_SYNC_PROTOCOL=1.0.0 cargo test --test sync --test sync_retention --locked

check:
	$(PYTHON) scripts/bundle_catalog.py --check
	$(PYTHON) scripts/sync_schema.py --check
	$(PYTHON) scripts/sync_vectors.py --check
	cargo fmt --all -- --check
	cargo clippy --all-targets --locked -- -D warnings
	$(MAKE) test

package: build
	$(PYTHON) scripts/package.py --target "$$(rustc -vV | sed -n 's/^host: //p')"

# Propose a software version, prepare it, then confirm the commit, tag and push.
release:
	$(PYTHON) scripts/release.py $(ARGS)
