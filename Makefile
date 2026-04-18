BINARY     := acpa
MODULE     := github.com/Eweka01/aws-container-posture-auditor
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -s -w -X main.version=$(VERSION)
BUILD_DIR  := dist

.PHONY: build test lint fmt clean release help

build: ## Build the binary for the current platform
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/acpa

test: ## Run all tests with race detector
	go test ./... -race -cover

lint: ## Run golangci-lint
	golangci-lint run ./...

fmt: ## Check formatting
	@files=$$(gofmt -l .); if [ -n "$$files" ]; then echo "Unformatted files:\n$$files"; exit 1; fi

clean: ## Remove build artifacts
	rm -f $(BINARY) coverage.out
	rm -rf $(BUILD_DIR) posture-report/

release: ## Cross-compile for all platforms into dist/
	@mkdir -p $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-amd64   ./cmd/acpa
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-arm64   ./cmd/acpa
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-darwin-amd64  ./cmd/acpa
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-darwin-arm64  ./cmd/acpa
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe ./cmd/acpa
	@ls -lh $(BUILD_DIR)/

sample: ## Regenerate the sample HTML report
	go run ./cmd/gensample

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
