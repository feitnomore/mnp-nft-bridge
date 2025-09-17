# Copyright 2025 Marcelo Parisi (github.com/feitnomore)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

GIT_TAG ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")
VERSION ?= $(GIT_TAG)

CGO_ENABLED := 0
GO_BIN := go
GO_VULN := govulncheck
GO_INPUT := ./cmd/mnp-nft-bridge/
BUILD_FLAGS := build -ldflags="-s -w -X main.version=$(VERSION)"
BAZEL_OPTS := --output_base=.bazel
CONTAINER_BIN := docker
CONTAINER_OPTS := --rm=false --no-cache
REPOSITORY := kubevirtmanager
GOFMT_BIN := gofmt
GOLINT := golangci-lint
GOIMPORTS := goimports

# Default Target
.PHONY: all
all : mnp-nft-bridge

# Build the Binary
.PHONY: mnp-nft-bridge
mnp-nft-bridge: fmt mod-tidy imports lint
	CGO_ENABLED=$(CGO_ENABLED) $(GO_BIN) $(BUILD_FLAGS) $(GO_INPUT)

# Module Management
.PHONY: mod-vendor mod-update mod-get mod-download mod-tidy mod-clean
mod-vendor:
	$(GO_BIN) mod vendor

mod-update:
	$(GO_BIN) get -u

mod-get:
	$(GO_BIN) get

mod-download:
	$(GO_BIN) mod download

mod-tidy:
	$(GO_BIN) mod tidy

mod-clean:
	$(GO_BIN) clean -modcache

# Cleaning
.PHONY: clean clean-all super-clean
clean:
	rm -rf mnp-nft-bridge
	rm -rf .work
	$(GO_BIN) clean -modcache

clean-all:
	rm -rf mnp-nft-bridge
	rm -rf .work
	rm -rf coverage.*
	rm -rf tmp
	$(GO_BIN) clean -modcache

super-clean: clean-all
	./hack/clean-docker.sh

# Container Images
.PHONY: image-build local-image-build image-build-debug local-image-build-debug image-push image-clean
image-build: 
	$(CONTAINER_BIN) build -t $(REPOSITORY)/mnp-nft-bridge:$(VERSION) . $(CONTAINER_OPTS)

local-image-build: 
	$(CONTAINER_BIN) build -t mnp-nft-bridge:$(VERSION) . $(CONTAINER_OPTS)

image-build-debug: 
	$(CONTAINER_BIN) build -t $(REPOSITORY)/mnp-nft-bridge:$(VERSION) -f ./Dockerfile.debug . $(CONTAINER_OPTS)

local-image-build-debug: 
	$(CONTAINER_BIN) build -t mnp-nft-bridge:$(VERSION) -f ./Dockerfile.debug . $(CONTAINER_OPTS)

image-push:
	$(CONTAINER_BIN) push $(REPOSITORY)/mnp-nft-bridge:$(VERSION) 

image-clean:
	$(CONTAINER_BIN) rmi $(REPOSITORY)/mnp-nft-bridge:$(VERSION) --force

# Linting and Formatting
.PHONY: lint fmt vet imports
lint:
	$(GOLINT) --config .golangci.yaml run

fmt:
	find ./pkg/ -name '*.go' -type f -print0 | xargs -0 $(GOFMT_BIN) -s -w
	find ./cmd/ -name '*.go' -type f -print0 | xargs -0 $(GOFMT_BIN) -s -w

vet:
	$(GO_BIN) vet ./cmd/...
	$(GO_BIN) vet ./pkg/...

imports: fmt
	find ./pkg/ -name '*.go' -type f -print0 | xargs -0 $(GOIMPORTS) -w
	find ./cmd/ -name '*.go' -type f -print0 | xargs -0 $(GOIMPORTS) -w

# Testing and Coverage
.PHONY: test test-verbose test-coverage coverage-report coverage-report-html coverage-report-txt
test: mnp-nft-bridge
	$(GO_BIN) test ./cmd/... ./pkg/...

test-verbose: mnp-nft-bridge
	$(GO_BIN) test -v ./cmd/... ./pkg/...

test-coverage: mnp-nft-bridge
	$(GO_BIN) test -v -cover ./cmd/... ./pkg/...

coverage-report-html: mnp-nft-bridge
	$(GO_BIN) test -coverprofile=coverage.out ./cmd/... ./pkg/...
	$(GO_BIN) tool cover -html=coverage.out -o coverage.html

coverage-report-txt: mnp-nft-bridge
	$(GO_BIN) test -coverprofile=coverage.out ./cmd/... ./pkg/...
	$(GO_BIN) tool cover -func=coverage.out -o coverage.txt

coverage-report: mnp-nft-bridge
	$(GO_BIN) test -coverprofile=coverage.out ./cmd/... ./pkg/...
	$(GO_BIN) tool cover -func=coverage.out

# Build Deps
deps:
	$(GO_BIN) install golang.org/x/tools/cmd/goimports@latest
	$(GO_BIN) install golang.org/x/vuln/cmd/govulncheck@latest
	$(GO_BIN) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Vuln Check
.PHONY: vuln-check
vuln-check:
	$(GO_VULN) ./cmd/... ./pkg/...

# HELP
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Available targets:"
	@echo "  all                     - Build the main binary with all checks (default)."
	@echo "  mnp-nft-bridge          - Build the main binary with formatting and linting."
	@echo ""
	@echo "  --- Module Management ---"
	@echo "  mod-vendor              - Vendor Go modules."
	@echo "  mod-update              - Update Go module dependencies to latest versions."
	@echo "  mod-download            - Download Go module dependencies."
	@echo "  mod-tidy                - Tidy Go module dependencies."
	@echo "  mod-clean               - Clean Go module cache."
	@echo ""
	@echo "  --- Cleaning ---"
	@echo "  clean                   - Clean build artifacts and Go module cache."
	@echo "  clean-all               - Clean more extensively."
	@echo "  super-clean             - Perform all cleaning steps and clean Docker images."
	@echo ""
	@echo "  --- Container Images ---"
	@echo "  image-build             - Build container image and tag for repository."
	@echo "  local-image-build       - Build container image and tag locally."
	@echo "  image-build-debug       - Build debug container image for repository."
	@echo "  local-image-build-debug - Build debug container image locally."
	@echo "  image-push              - Push container image to repository."
	@echo "  image-clean             - Remove container image from local Docker."
	@echo ""
	@echo "  --- Linting and Formatting ---"
	@echo "  lint                    - Run linters (golangci-lint)."
	@echo "  fmt                     - Format Go source code (gofmt)."
	@echo "  vet                     - Run Go vet analysis."
	@echo "  imports                 - Fix Go import paths (goimports)."
	@echo ""
	@echo "  --- Testing and Coverage ---"
	@echo "  test                    - Run unit tests."
	@echo "  test-verbose            - Run unit tests verbosely."
	@echo "  test-coverage           - Run unit tests and show coverage."
	@echo "  coverage-report-html    - Generate HTML coverage report."
	@echo "  coverage-report-txt     - Generate text coverage report."
	@echo "  coverage-report         - Generate function coverage report to console."
	@echo ""
	@echo "  --- Vulnerability Check ---"
	@echo "  vuln-check               - Check vulnerabilities."
	@echo ""
	@echo "  --- Build Deps ---"
	@echo "  deps                    - Install Go development tools (goimports, golangci-lint)."
	@echo ""