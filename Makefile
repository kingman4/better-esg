.PHONY: build build-cli run tidy test test-integration test-coverage up down clean clean-test templ-generate

# Detect host OS/arch for cross-compiling the CLI inside Docker
CLI_OS ?= $(shell uname -s | tr A-Z a-z)
CLI_ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

# Generate templ files (requires local Go)
templ-generate:
	go run github.com/a-h/templ/cmd/templ@v0.3.977 generate

# Build the server binary (requires local Go)
build: templ-generate
	go build -o server ./cmd/server

# Build the CLI binary via Docker (no local Go required)
build-cli:
	docker run --rm -v "$(PWD)":/app -w /app \
		-e GOOS=$(CLI_OS) -e GOARCH=$(CLI_ARCH) -e CGO_ENABLED=0 \
		golang:1.24-alpine sh -c "apk add --no-cache git && go mod tidy && go build -buildvcs=false -o esg-cli ./cmd/cli"

# Resolve dependencies via Docker (no local Go required)
tidy:
	docker run --rm -v "$(PWD)":/app -w /app golang:1.24-alpine sh -c "apk add --no-cache git && go mod tidy"

# Run locally (requires Postgres running)
run:
	go run ./cmd/server

# Run unit tests locally (requires local Go + templ)
test: templ-generate
	go test ./...

# Run unit tests via Docker (no local Go required)
# Uses Dockerfile.test for layer caching — only re-downloads deps when go.mod changes.
test-docker:
	docker build -f Dockerfile.test -t better-esg-test .
	docker run --rm better-esg-test

# Run all tests including integration via Docker (no local Go required)
# Reuses the cached test image; mounts Docker socket for testcontainers.
test-integration:
	docker build -f Dockerfile.test -t better-esg-test .
	docker run --rm \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-e TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
		better-esg-test go test -tags=integration ./...

# Start all services (web app + database)
up:
	docker compose up --build

# Build CLI + start all services
up-all: build-cli
	docker compose up --build

# Stop all services
down:
	docker compose down

# Stop and remove volumes
clean:
	docker compose down -v

# Run unit tests with coverage report (opens in browser)
test-coverage:
	docker build -f Dockerfile.test -t better-esg-test .
	docker run --rm better-esg-test sh -c \
		"go test -coverprofile=/tmp/cover.out ./... && go tool cover -func=/tmp/cover.out"

# Remove cached test image to free disk space
clean-test:
	docker rmi better-esg-test 2>/dev/null || true
