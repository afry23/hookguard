BIN     := hookguard
PREFIX  ?= /usr/local
DESTDIR ?=
GOFLAGS := -ldflags="-s -w"

.PHONY: all deps build install uninstall test lint clean

all: build

## deps: download modules and tidy go.sum
deps:
	go mod tidy

## build: compile the binary (runs deps first)
build: deps
	go build $(GOFLAGS) -o $(BIN) ./cmd/hookguard

## install: install to $(DESTDIR)$(PREFIX)/bin  (default: /usr/local/bin)
install: build
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
	@echo "Installed → $(DESTDIR)$(PREFIX)/bin/$(BIN)"

## uninstall: remove the installed binary
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

## test: run all unit tests
test: deps
	go test -v -count=1 ./...

## lint: run golangci-lint (requires golangci-lint to be installed)
lint:
	golangci-lint run ./...

## clean: remove build artefacts
clean:
	rm -f $(BIN)

## help: print this message
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
