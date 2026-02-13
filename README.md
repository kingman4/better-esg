# FDA ESG NextGen Submission Platform

An open-source Go server and CLI for submitting electronic regulatory documents to the FDA via the ESG NextGen API. Handles the full submission lifecycle: credential exchange, file upload, finalization, status polling, and acknowledgement retrieval.

Licensed under Apache 2.0.

## Quick Start

```bash
git clone https://github.com/kingman4/better-esg.git
cd better-esg
cp .env.example .env    # edit with your FDA credentials
make up                  # builds CLI + starts server on :8080 + Postgres

# In another terminal:
./esg-cli send --file report.xml
```

One command to submit a file to FDA. No Go installation required — the CLI is cross-compiled via Docker.

## Architecture

```
cmd/
  server/       HTTP server entry point
  cli/          CLI client (esg-cli)
internal/
  config/       Environment-based configuration
  database/     Embedded SQL migrations (golang-migrate)
  fdaclient/    FDA ESG NextGen API client with retry
  repository/   PostgreSQL data access layer
  server/       HTTP handlers, routing, background poller
```

The server exposes a REST API that orchestrates multi-step FDA submissions. A background poller periodically checks FDA for status updates on in-flight submissions and stores acknowledgements locally.

## Configuration

All configuration is via environment variables. Copy `.env.example` and fill in the required values.

### Required

| Variable | Description |
|---|---|
| `ENCRYPTION_KEY` | 64-character hex string (32 bytes) for AES-256-GCM encryption of temp credentials. Generate with `openssl rand -hex 32` |

### FDA API

| Variable | Default | Description |
|---|---|---|
| `FDA_CLIENT_ID` | | OAuth2 client ID for FDA ESG NextGen |
| `FDA_CLIENT_SECRET` | | OAuth2 client secret |
| `FDA_USER_EMAIL` | | Your FDA user email (server auto-resolves user_id and company_id) |
| `FDA_ENVIRONMENT` | `test` | `test` or `prod` |
| `FDA_EXTERNAL_BASE_URL` | `https://external-api-esgng.fda.gov` | Auth and metadata API |
| `FDA_UPLOAD_BASE_URL` | `https://upload-api-esgng.fda.gov` | File upload API |

### Server

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `DATABASE_URL` | built from DB_* vars | PostgreSQL connection string |
| `DB_HOST` | `localhost` | Database host |
| `DB_PORT` | `5432` | Database port |
| `DB_USER` | `esg` | Database user |
| `DB_PASSWORD` | `esg` | Database password |
| `DB_NAME` | `esg` | Database name |
| `DB_SSLMODE` | `disable` | SSL mode |
| `STATUS_POLL_INTERVAL` | `60s` | How often to poll FDA for in-flight submission updates (0 = disabled) |
| `AUTH_DISABLED` | `false` | Set to `true` to skip API key auth (local dev) |

## Running

### Docker Compose (recommended)

```bash
docker compose up --build
```

This starts the Go server on port 8080 and PostgreSQL 16 on port 5432. Migrations run automatically on startup.

### Local development

Requires Go 1.24+ and a running PostgreSQL instance.

```bash
# Set environment variables (or source .env)
export DATABASE_URL=postgres://esg:esg@localhost:5432/esg?sslmode=disable
export ENCRYPTION_KEY=$(openssl rand -hex 32)

make build
./server
```

## CLI Usage

The CLI is a standalone binary that talks to the server's REST API.

```bash
export ESG_SERVER_URL=http://localhost:8080    # optional, this is the default
```

### Send a submission (recommended)

The `send` command runs the full FDA pipeline in one shot — create, initiate, upload, and finalize:

```bash
./esg-cli send --file report.xml
```

The server auto-resolves your FDA user ID and company ID from `FDA_USER_EMAIL` in `.env`. Submission name defaults to the filename (override with `--name`).

Other optional flags: `--type ANDA` (default), `--center CDER` (default), `--protocol API` (default), `--desc "..."`.

After sending, track your submission:

```bash
./esg-cli status --id <submission-id>
./esg-cli acks --id <submission-id>
```

### Authentication

The Docker Compose setup runs with `AUTH_DISABLED=true` by default, so the CLI works with no API key — the server uses a default org/user for all requests.

For production (multi-tenant), remove `AUTH_DISABLED` and provision API keys with the `seed-key` command:

```bash
./esg-cli seed-key --org "My Company" --slug myco --email you@company.com
export ESG_API_KEY=<printed-key>
```

### Other commands

```bash
./esg-cli list --table           # human-friendly table
./esg-cli list                   # JSON output
./esg-cli status --id <id>       # poll FDA for current status
./esg-cli acks --id <id>         # view stored acknowledgements
```

### Advanced: individual pipeline steps

For multi-file submissions or debugging, you can run each step separately:

```bash
# Create
ID=$(./esg-cli create --name "Q1 Report" --type ANDA --files 2 | jq -r '.id')

# Initiate FDA workflow
./esg-cli submit --id $ID

# Upload files (repeat for each file)
./esg-cli upload --id $ID --file ./file1.xml
./esg-cli upload --id $ID --file ./file2.xml

# Finalize
./esg-cli finalize --id $ID
```

## API Endpoints

All endpoints except `/health` require an `Authorization: Bearer <api-key>` header (unless `AUTH_DISABLED=true`).

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check with DB connectivity |
| `POST` | `/api/v1/submissions` | Create a new submission |
| `GET` | `/api/v1/submissions` | List submissions (`?limit=&offset=`) |
| `GET` | `/api/v1/submissions/{id}` | Get a single submission |
| `POST` | `/api/v1/submissions/{id}/submit` | Initiate FDA workflow |
| `POST` | `/api/v1/submissions/{id}/files` | Upload a file (multipart) |
| `POST` | `/api/v1/submissions/{id}/finalize` | Finalize and submit to FDA |
| `GET` | `/api/v1/submissions/{id}/status` | Poll FDA for current status |
| `GET` | `/api/v1/submissions/{id}/acknowledgements` | List stored acknowledgements |

## Submission Workflow

```
draft → INITIALIZED
  ↓ submit
initiated → CREDENTIALS_PENDING → PAYLOAD_PENDING → UPLOAD_PENDING
  ↓ upload files
file_uploaded → FILES_UPLOADING
  ↓ finalize
submitted → SUBMIT_PENDING → SUBMITTED
  ↓ FDA processing (background poller)
completed → ACCEPTED  or  failed → REJECTED
```

Each state transition is logged to `workflow_state_log` for audit purposes.

## Testing

```bash
# Unit tests only (no Docker required)
make test

# All tests including integration (starts a disposable Postgres container)
make test-integration
```

Integration tests use `testcontainers-go` for disposable PostgreSQL containers and `httptest` for mock FDA servers. FDA endpoints are never hit in CI.

## Build

```bash
make up             # builds CLI + starts server and Postgres
make build          # server binary → ./server (requires local Go)
make build-cli      # CLI binary → ./esg-cli (via Docker, no local Go needed)
```

Both produce static binaries with no external dependencies. `make build-cli` cross-compiles for your host OS/architecture automatically.

## Key Design Decisions

**Go** was chosen over Node.js/TypeScript for single-binary deployment, strong file streaming performance (submissions up to 1TB), and compile-time type safety for compliance-sensitive FDA work.

**Retry with backoff** on all FDA API calls: exponential backoff for most endpoints, linear backoff for uploads. Transient failures (429, 5xx) are retried; permanent errors (4xx) fail immediately.

**Streaming uploads** via `io.ReadSeeker` + `io.MultiReader` — file content is never fully buffered in memory, enabling large file submissions.

**Background status poller** checks FDA for in-flight submissions on a configurable interval and stores acknowledgements locally with deduplication.
