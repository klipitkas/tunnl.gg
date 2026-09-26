.PHONY: build build-small build-tiny build-all build-dev test lint vuln run clean tidy size-check install

# Binary name
BINARY=tunnl

# Build directory
BUILD_DIR=bin

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod

# Version info embedded in the binary and logged at startup
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION_FLAGS=-X main.version=$(VERSION) -X main.commit=$(COMMIT)

# Linker flags for size optimization
# -s: Omit symbol table and debug info
# -w: Omit DWARF symbol table
LDFLAGS=-s -w $(VERSION_FLAGS)

# Build tags to exclude unnecessary features
BUILD_TAGS=

# Default target: optimized build
build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/tunnl

# Small build with all optimizations
build-small: clean
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY) ./cmd/tunnl
	@echo "Binary size: $$(du -h $(BUILD_DIR)/$(BINARY) | cut -f1)"

# Tiny build: smallest possible binary (requires upx)
build-tiny: build-small
	@command -v upx >/dev/null 2>&1 && upx --best --lzma $(BUILD_DIR)/$(BINARY) || echo "upx not installed, skipping compression"
	@echo "Final binary size: $$(du -h $(BUILD_DIR)/$(BINARY) | cut -f1)"

# Build for multiple platforms
build-all: clean
	@mkdir -p $(BUILD_DIR)
	# Linux AMD64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./cmd/tunnl
	# Linux ARM64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-linux-arm64 ./cmd/tunnl
	# Darwin AMD64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 ./cmd/tunnl
	# Darwin ARM64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 ./cmd/tunnl
	@echo "Built binaries:"
	@ls -lh $(BUILD_DIR)/

# Development build (faster, with debug info)
build-dev:
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -ldflags="$(VERSION_FLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/tunnl

# Run tests
test:
	$(GOTEST) -v ./...

# Run linters (requires golangci-lint v2)
lint:
	golangci-lint run ./...

# Check for known vulnerabilities in reachable code
vuln:
	$(GOCMD) run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

# Run the application
run: build-dev
	$(BUILD_DIR)/$(BINARY)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY)

# Tidy dependencies
tidy:
	$(GOMOD) tidy

# Show binary size comparison
size-check: build build-small
	@echo "\n=== Binary Size Comparison ==="
	@echo "Standard build: $$(du -h $(BUILD_DIR)/$(BINARY) | cut -f1)"

# Install to system
install: build-small
	sudo cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "Installed to /usr/local/bin/$(BINARY)"
