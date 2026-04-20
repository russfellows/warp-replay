TAG    := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
FULL   := $(shell git rev-parse HEAD 2>/dev/null || echo "dev")
DATE   := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VER    := $(patsubst v%,%,$(TAG))

# Binary name and default install destination
BINARY  := warp
DESTDIR := /usr/local/bin

LDFLAGS := -s -w \
	-X github.com/minio/warp/pkg.ReleaseTag=$(TAG) \
	-X github.com/minio/warp/pkg.Version=$(VER) \
	-X github.com/minio/warp/pkg.CommitID=$(FULL) \
	-X github.com/minio/warp/pkg.ShortCommitID=$(COMMIT) \
	-X github.com/minio/warp/pkg.ReleaseTime=$(DATE)

.PHONY: build clean test install

build:
	go build -o $(BINARY) -ldflags "$(LDFLAGS)" .
	@echo ""
	@echo "Built: $(BINARY)  (tag=$(TAG), commit=$(COMMIT))"
	@echo ""
	@echo "To install system-wide (default: $(DESTDIR)):"
	@echo "  sudo install -m 0755 $(BINARY) $(DESTDIR)/$(BINARY)"
	@echo ""
	@echo "To install to a custom location, pass DESTDIR:"
	@echo "  sudo make install DESTDIR=/usr/bin"
	@echo "  make install DESTDIR=\$$HOME/.local/bin   # no sudo needed for user dirs"

install: build
	install -m 0755 $(BINARY) $(DESTDIR)/$(BINARY)
	@echo "Installed $(BINARY) -> $(DESTDIR)/$(BINARY)"

clean:
	rm -f $(BINARY)

test:
	go test ./...
