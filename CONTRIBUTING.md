# Contributing to FDA ESG NextGen Submission Platform

Thank you for your interest in contributing! This guide will help you get started.

## Getting Started

### Prerequisites

- Docker and Docker Compose (required for all workflows)
- Go 1.24+ (optional — only needed for local development without Docker)

### Setup

```bash
git clone https://github.com/kingman4/better-esg.git
cd better-esg
cp .env.example .env
make up
```

The server starts at `http://localhost:8080` with a local PostgreSQL database.

## Development Workflow

1. Fork the repository and create a branch from `dev`
2. Make your changes
3. Run the tests: `make test-docker`
4. Run integration tests if you changed database or FDA client code: `make test-integration`
5. Open a pull request against `dev`

PRs into `main` must come from the `dev` branch. Feature branches should target `dev`.

## Running Tests

```bash
# Unit tests (via Docker, no local Go required)
make test-docker

# Unit + integration tests (spins up a disposable Postgres via testcontainers)
make test-integration

# Unit tests locally (requires Go 1.24+ and templ)
make test
```

Integration tests use `testcontainers-go` for disposable PostgreSQL containers and `httptest` for mock FDA servers. **FDA endpoints are never hit in CI or tests.**

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use table-driven tests with `testify/assert`
- Integration tests must use the `//go:build integration` build tag
- Keep changes focused — one concern per PR

## Project Structure

```
cmd/server/       Entry point
cmd/cli/          CLI client
internal/
  config/         Environment-based configuration
  database/       SQL migrations (golang-migrate, embedded via go:embed)
  fdaclient/      FDA API client with retry logic
  repository/     PostgreSQL data access layer
  server/         HTTP handlers, routing, middleware, background poller
  auth/           JWT, password hashing, TOTP/MFA
  crypto/         AES-256-GCM encryption
```

## Adding Database Migrations

Migrations use golang-migrate's sequential numbering format:

```bash
# Find the next number
ls internal/database/migrations/ | tail -2

# Create up and down files
touch internal/database/migrations/000019_your_change.up.sql
touch internal/database/migrations/000019_your_change.down.sql
```

Every `up` migration must have a corresponding `down` migration.

## Reporting Issues

Open an issue on GitHub with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Environment details (OS, Docker version)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
