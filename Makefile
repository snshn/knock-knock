# Makefile for knock-knock

all: build
.PHONY: all

build:
	@cargo build --locked
.PHONY: build

clean:
	@cargo clean
.PHONY: clean

format:
	@cargo fmt --all --
.PHONY: format

format_check:
	@cargo fmt --all -- --check
.PHONY: format

install:
	@cargo install --force --locked --path .
.PHONY: install

lint:
	@cargo clippy --fix --allow-dirty --allow-staged
# 	@cargo fix --allow-dirty --allow-staged
.PHONY: lint

lint_check:
	@cargo clippy --
.PHONY: lint_check

uninstall:
	@cargo uninstall
.PHONY: uninstall

test: build
	@cargo test --locked
.PHONY: build

update-lock-file:
	@cargo update
.PHONY: clean
