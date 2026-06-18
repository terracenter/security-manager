.PHONY: build clean test vet

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

build:
	go build -ldflags="-X main.Version=$(VERSION)" -o security-manager-ng .

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f security-manager-ng

.DEFAULT_GOAL := build
