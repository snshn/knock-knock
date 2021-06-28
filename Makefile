# Makefile for knock-knock

all: build
.PHONY: all

build:
	@cargo build --locked
.PHONY: build

test: build
	@cargo test --locked
	@cargo fmt --all -- --check
.PHONY: build

lint:
	@cargo fmt --all --
.PHONY: lint

install:
	@cargo install --force --locked --path .
.PHONY: install

uninstall:
	@cargo uninstall
.PHONY: uninstall

clean:
	@cargo clean
.PHONY: clean
