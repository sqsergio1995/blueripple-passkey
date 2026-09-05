BINARY_NAME := blueripple-passkey
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

.PHONY: all build dist test check clean help

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./main.go

dist:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY_NAME)-linux-amd64 ./main.go
	cd dist && sha256sum $(BINARY_NAME)-linux-amd64 > SHA256SUMS

test:
	go test ./... -timeout 60s

check:
	go vet ./...
	go test ./... -race -timeout 60s

clean:
	rm -f -- $(BINARY_NAME)

help:
	@echo "BlueRipple Passkey"
	@echo "  make build  Build the Linux binary"
	@echo "  make dist   Build a checksummed x86-64 release binary"
	@echo "  make test   Run unit tests"
	@echo "  make check  Run vet and race-enabled tests"
