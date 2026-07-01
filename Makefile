BINARY  := aws-use
VERSION := $(shell cat VERSION)
PKG     := github.com/dbaggott/aws-use/internal/cli
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION)
PREFIX  ?= $(HOME)/.local

.PHONY: build install uninstall test lint shelltest fmt clean help

help:
	@echo "Targets: build install uninstall test lint shelltest fmt clean"
	@echo "  install honors PREFIX (default: $(HOME)/.local) -> PREFIX/bin/$(BINARY)"

build:
	go build -ldflags '$(LDFLAGS)' -o $(BINARY) .

install: build
	@install -d "$(PREFIX)/bin"
	@install -m 0755 $(BINARY) "$(PREFIX)/bin/$(BINARY)"
	@echo "Installed $(PREFIX)/bin/$(BINARY)"

uninstall:
	@rm -f "$(PREFIX)/bin/$(BINARY)"
	@echo "Removed $(PREFIX)/bin/$(BINARY)"

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

# Exercise the shellenv hook under every shell we support (bash 3.2 + zsh).
shelltest: build
	bash test/shell_hook.sh ./$(BINARY)
	@if command -v zsh >/dev/null; then zsh test/shell_hook.sh ./$(BINARY); else echo "(zsh not present, skipping)"; fi

fmt:
	gofmt -w .

clean:
	rm -f $(BINARY)
	rm -rf dist
