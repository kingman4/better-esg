.PHONY: build build-cli run tidy test test-integration up down clean

# Build the server binary
build:
	go build -o server ./cmd/server

# Build the CLI binary
build-cli:
	go build -o esg-cli ./cmd/cli

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

# Start all services via Docker Compose
up:
	docker compose up --build

# Stop all services
down:
	docker compose down

# Stop and remove volumes
clean:
	docker compose down -v
