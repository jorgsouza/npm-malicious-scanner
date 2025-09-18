# Makefile for npm-malicious-scanner

BINARY_NAME=npm-malicious
BUILD_DIR=bin

.PHONY: all build clean

all: build

build:
	@echo "Building static binary..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/npm-malicious

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
