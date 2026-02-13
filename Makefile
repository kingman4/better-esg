.PHONY: build build-cli run tidy test test-integration up down clean

# Detect host OS/arch for cross-compiling the CLI inside Docker
CLI_OS ?= $(shell uname -s | tr A-Z a-z)
CLI_ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

# Build the server binary (requires local Go)
build:
	go build -o server ./cmd/server

# Build the CLI binary via Docker (no local Go required)
build-cli:
	docker run --rm -v "$(PWD)":/app -w /app \
		-e GOOS=$(CLI_OS) -e GOARCH=$(CLI_ARCH) -e CGO_ENABLED=0 \
		golang:1.24-alpine sh -c "go mod tidy && go build -o esg-cli ./cmd/cli"

# Resolve dependencies via Docker (no local Go required)
tidy:
	docker run --rm -v "$(PWD)":/app -w /app golang:1.24-alpine go mod tidy

# Run locally (requires Postgres running)
run:
	go run ./cmd/server

# Resolve deps and run unit tests
test: tidy
	go test ./...

# Resolve deps and run all tests including integration (requires Docker)
# TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE fixes Colima socket mounting
test-integration: tidy
	TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock go test -tags=integration ./...

# Build CLI + start all services (one command to get running)
up: build-cli
	docker compose up --build

# Stop all services
down:
	docker compose down

# Stop and remove volumes
clean:
	docker compose down -v
