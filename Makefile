GO ?= go
PYTHON ?= python3

.PHONY: test test-race vet build build-linux run-api run-engine verify-m2-linux ml

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./internal/...

vet:
	$(GO) vet ./...

build:
	$(GO) build ./cmd/ngfw-api ./cmd/ngfw-engine

build-linux:
	CGO_ENABLED=0 GOOS=linux $(GO) build -trimpath ./cmd/ngfw-api ./cmd/ngfw-engine ./cmd/ngfw-proxy

run-api:
	$(GO) run ./cmd/ngfw-api

run-engine:
	$(GO) run ./cmd/ngfw-engine

verify-m2-linux:
	sudo bash scripts/verify-m2-linux.sh

ml:
	$(PYTHON) ml/service/app.py
