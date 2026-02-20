.PHONY: build build-cli run tidy test test-integration up down clean templ-generate

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
test-docker:
	docker run --rm -v "$(PWD)":/app -w /app golang:1.24-alpine sh -c \
		"apk add --no-cache git && go run github.com/a-h/templ/cmd/templ@v0.3.977 generate && go get github.com/a-h/templ@v0.3.977 && go mod tidy && go test ./..."

# Resolve deps and run all tests including integration (requires Docker)
# TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE fixes Colima socket mounting
test-integration: tidy
	TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock go test -tags=integration ./...

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
