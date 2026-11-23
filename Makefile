BIN    ?= ssh-handshake
PREFIX ?= /usr/local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test install clean
build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/ssh-handshake

test:
	go vet ./...
	go test ./...

install: build
	install -o root -g root -m 0755 $(BIN) $(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN)
