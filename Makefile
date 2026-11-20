CGO_ENABLED ?= 0
LDFLAGS     := -s -w
WIN_LDFLAGS := -s -w -H=windowsgui
DIST_DIR    := dist

.PHONY: all vet test test-race build build-server build-core build-windows build-0ghost clean

all: build

vet:
	GFT_NO_SYSPROXY=1 go vet ./cmd/... ./internal/...

test:
	GFT_NO_SYSPROXY=1 go test -count=1 ./cmd/... ./internal/...

test-race:
	GFT_NO_SYSPROXY=1 go test -race -v ./cmd/... ./internal/...

build: build-server build-core build-windows build-0ghost

build-server:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/gft-server-linux-amd64 ./cmd/gft-server
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/gft-server-linux-arm64 ./cmd/gft-server

build-core:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/gft-core-linux-amd64 ./cmd/gft-core
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/gft-core-linux-arm64 ./cmd/gft-core

build-windows:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(WIN_LDFLAGS)" -o $(DIST_DIR)/GhostFrame-Pro.exe ./cmd/gft-client-gui

build-0ghost:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/0ghost-linux-arm64 ./cmd/0ghost

clean:
	rm -rf $(DIST_DIR)
