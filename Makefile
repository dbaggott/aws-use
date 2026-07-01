BINARY  := aws-use
VERSION := $(shell cat VERSION)
PKG     := github.com/dbaggott/aws-use/internal/cli
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION)
PREFIX  ?= $(HOME)/.local

.PHONY: build install uninstall test lint fmt clean help

help:
	@echo "Targets: build install uninstall test lint fmt clean"
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
	go vet ./...
	@test -z "$$(gofmt -l . )" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	go test ./...

lint:
	go vet ./...
	gofmt -l .

fmt:
	gofmt -w .

clean:
	rm -f $(BINARY)
	rm -rf dist
