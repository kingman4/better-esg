# Security Review — 2026-02-20

## Overall Assessment

Strong security fundamentals: parameterized SQL, bcrypt password hashing, AES-256-GCM encryption, proper JWT validation, HMAC-signed webhooks, no unsafe/CGO. Issues below are hardening items for production readiness.

---

## HIGH Severity

### 1. Path Traversal in File Uploads
- **Files:** `internal/server/upload.go:98`, `internal/server/chunked_upload.go:342`
- Upload filenames used directly in storage keys without sanitization (`id + "/" + header.Filename`).
- Storage layer `validateKey()` rejects `..` (mitigating factor), but defense-in-depth requires `filepath.Base()` at handler level.
- **Fix:** `filename := filepath.Base(header.Filename)` before constructing storage key.

### 2. No Rate Limiting on Authentication
- **Files:** `internal/server/server.go`, `internal/server/auth_handlers.go`
- No rate limiting on `/api/v1/auth/login`, `/api/v1/auth/refresh`, or MFA verification.
- Brute-force attacks against passwords and TOTP codes are unthrottled.
- **Fix:** Add middleware rate limiter (e.g., `golang.org/x/time/rate` or token bucket per IP).

### 3. Row-Level Security (RLS) Defined but Not Activated
- **File:** `internal/database/migrations/000009_row_level_security.up.sql`
- RLS policies reference `current_setting('app.current_org_id')` but no application code sets this session variable.
- **Fix:** Either wire up `SET LOCAL app.current_org_id = ...` per request, or remove RLS and rely on application-level `org_id` filtering (which is consistently applied).

### 4. TOTP Secrets Stored Unencrypted
- **File:** `internal/database/migrations/000003_users.up.sql:8`
- MFA secrets stored as plaintext `VARCHAR(255)`. Database compromise exposes all TOTP seeds.
- **Fix:** Encrypt with existing AES-256-GCM (`internal/crypto/aes.go`) before storing.

---

## MEDIUM Severity

### 5. No CSRF Protection on Web Forms
- **File:** `internal/server/web_handlers.go`
- POST endpoints for login, MFA verification, and logout lack CSRF tokens.
- SameSite=Lax cookies provide partial mitigation.
- **Fix:** Generate and validate CSRF nonce tokens in templ templates for all state-changing forms.

### 6. Missing Security Headers
- **File:** `internal/server/server.go`
- No `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, or `Referrer-Policy` headers.
- **Fix:** Single middleware to set all security headers on every response.

### 7. JWT Role Not Re-verified on Each Request
- **File:** `internal/server/auth_handlers.go:122`
- User role baked into JWT at sign time. Role changes (e.g., admin demotes user) not reflected until token refresh (up to 15 min).
- **Fix:** Shorten access token TTL or check role from DB on sensitive operations.

### 8. No Database Connection Pool Limits
- **File:** `internal/server/server.go:96`
- `sql.Open()` called without `SetMaxOpenConns()` / `SetMaxIdleConns()` / `SetConnMaxLifetime()`.
- Under load, can exhaust database connections.
- **Fix:** Set reasonable limits (e.g., 25 open, 5 idle, 5 min lifetime).

### 9. JWT Secret Can Be Empty When Auth Is Enabled
- **File:** `internal/config/config.go:99-102`
- Current: `if !authDisabled && jwtSecret != "" && len(jwtSecret) < 32` — allows empty secret.
- **Fix:** Change to `if !authDisabled && (jwtSecret == "" || len(jwtSecret) < 32)`.

### 10. Webhook Secrets Stored Unencrypted
- **File:** `internal/repository/webhooks.go:16`
- Webhook signing secrets stored as plaintext in database.
- **Fix:** Encrypt at rest with AES-256-GCM, same as FDA credentials.

### 11. Error Messages Leak Internal Details
- **Files:** `internal/server/upload.go:86`, `internal/server/chunked_upload.go:99`
- Raw Go error strings from `ParseMultipartForm` and JSON decoder returned to clients.
- **Fix:** Return generic error messages; log details server-side only.

---

## LOW Severity

### 12. No `Secure` Flag on Cookies
- **File:** `internal/server/web_middleware.go:78-88`
- Auth cookies don't set `Secure: true`, so they'd transmit over HTTP.
- **Fix:** Set `Secure: true` conditionally based on environment (production = true).

### 13. No `USER` Directive in Dockerfile
- **File:** `Dockerfile`
- Production image runs as root by default.
- **Fix:** Add `RUN addgroup -S app && adduser -S app -G app` and `USER app`.

### 14. DB SSL Mode Defaults to `disable`
- **File:** `internal/config/config.go:65`
- Acceptable for local Docker dev, but risky default for production.
- **Fix:** Consider defaulting to `require`, or validate in production environments.

### 15. Default Admin Credentials Logged
- **File:** `internal/server/server.go:374`
- When `AUTH_DISABLED=true`, logs `email=admin@localhost password=admin`.
- **Fix:** Remove password from log message or gate behind a debug flag.

### 16. Audit Log IP Behind Proxies
- **File:** `internal/repository/audit_log.go:61-67`
- Uses `r.RemoteAddr` without parsing `X-Forwarded-For`. Behind a reverse proxy, all audit entries show the proxy IP.
- **Fix:** Parse trusted `X-Forwarded-For` header when behind a known proxy.

---

## What's Done Well

| Area | Details |
|------|---------|
| SQL injection | All parameterized queries — no risk found |
| Password hashing | bcrypt cost 12 |
| Encryption | AES-256-GCM with random nonces, key validated at startup |
| JWT | Algorithm pinning (prevents `alg:none` attack), proper expiry |
| API keys | SHA-256 hashed, never stored raw |
| Webhook signing | HMAC-SHA256 with per-hook secrets |
| File storage | `validateKey()` rejects `..` and absolute paths |
| Refresh tokens | Hashed before storage, revocable per-user |
| Backup codes | bcrypt hashed, single-use enforced in DB |
| Dependencies | All pinned, no unsafe/CGO, no known vulnerabilities |
| HTTP clients | 30s timeouts, TLS verification enabled (no `InsecureSkipVerify`) |
| Audit trail | Comprehensive logging of sensitive operations |

---

## Recommended Priority Actions

1. Add rate limiting to auth endpoints
2. Sanitize filenames with `filepath.Base()` at handler level
3. Fix JWT secret validation to reject empty strings
4. Add security headers middleware
5. Encrypt TOTP and webhook secrets at rest
6. Set database connection pool limits
7. Add CSRF tokens to web forms
8. Add non-root `USER` directive to Dockerfile
