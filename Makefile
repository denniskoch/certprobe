BINARY := certprobe
MAIN   := .

# Target platforms
GOOS   := linux darwin windows
GOARCH := amd64 arm64

# Version metadata (requires git)
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
  -X github.com/denniskoch/certprobe/cmd.version=$(VERSION) \
  -X github.com/denniskoch/certprobe/cmd.commit=$(COMMIT) \
  -X github.com/denniskoch/certprobe/cmd.date=$(DATE)

build:
	@mkdir -p bin
	go build -ldflags='$(LDFLAGS)' -o bin/$(BINARY) $(MAIN)

build-all:
	@mkdir -p dist
	@for os in $(GOOS); do \
	  for arch in $(GOARCH); do \
	    ext=""; \
	    [ "$$os" = "windows" ] && ext=".exe"; \
	    echo ">> $$os/$$arch"; \
	    GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
	      go build -ldflags='$(LDFLAGS)' \
	      -o dist/$(BINARY)-$$os-$$arch$$ext $(MAIN); \
	  done; \
	done
	@echo "✅ All builds complete → dist/"

clean:
	rm -rf bin/  dist/