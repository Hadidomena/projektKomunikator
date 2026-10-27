# Projekt Komunikator

A small, self-hosted end-to-end encrypted messaging prototype built with Go, Astro, PostgreSQL, Nginx, and Docker Compose.

When client-side encryption is active, messages are encrypted in the browser with X25519, HKDF-SHA256, and AES-256-GCM via the Web Crypto API; the server stores only the ciphertext envelope and never receives the unwrapped private key. Accounts also get TOTP two-factor authentication, password reset by email, login history, and bot/honeypot protections.

> **Status: prototype.** The implementation is a learning project, not an audited secure messenger. See [Security model and limitations](#security-model-and-limitations) before using it for anything sensitive.

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Security model and limitations](#security-model-and-limitations)
- [Project layout](#project-layout)
- [Getting started](#getting-started)
- [Configuration reference](#configuration-reference)
- [API overview](#api-overview)
- [Data model](#data-model)
- [Development and testing](#development-and-testing)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

### Messaging

- **End-to-end encrypted messages** — X25519 ECDH key agreement, HKDF-SHA256 key derivation, AES-256-GCM encryption in the browser.
- **Encrypted attachments** — files are base64-encoded into the encrypted message payload (15 MB per file, 25 MB per message).
- **Inbox and sent views** — paginated lists, unread indicators, read receipts, and per-user soft deletion.
- **Markdown messages** — rendered with vendored `marked` and sanitized with DOMPurify on the client.
- **Key fingerprints** — users can display their own fingerprint and look up a recipient's key fingerprint before sending.
- **Dark/light theme** — follows the system preference and remembers the user's choice.

### Accounts and authentication

- **Registration and login** — JWT-based sessions (HS256, one-hour expiry).
- **TOTP 2FA** — RFC 6238, with the secret encrypted at rest in the database.
- **Password security** — Argon2id hashing, a server-side pepper, a 100k common-password blocklist (NCSC), and a live strength meter.
- **Password reset** — single-use, hashed tokens delivered by email and valid for one hour. Note that resetting the password does not re-wrap the E2EE private key (see [limitations](#limitations)).
- **Login monitoring** — login history, new-device detection, and email alerts for unrecognized devices.

### Security hardening

- Login-attempt lockout: a 1-minute lock after the first failure, a 5-minute lock from the third, and a permanent block on the fifth (cleared by a password reset).
- Per-account status persisted in PostgreSQL, plus per-IP rate limiting in Go and Nginx.
- CSRF tokens for selected state-changing authenticated endpoints.
- Hidden honeypot fields on login and registration, with attempted submissions recorded and rejected.
- CORS allow-list, strict security headers, HSTS, and a Content Security Policy.
- TLS for PostgreSQL connections inside the Compose network.

## Architecture

```text
                       https://localhost:8443
 Browser ─────────────────────────────────────────┐
   Astro pages + Web Crypto                       │
                                                  ▼
                                            ┌──────────┐
                                            │  Nginx   │  TLS, rate limits,
                                            │ :80/:443 │  security headers
                                            └────┬─────┘
                                /api/*           │           /*
                     ┌──────────────────────────┴───────────┐
                     ▼                                      ▼
              ┌─────────────┐                       ┌─────────────────┐
              │  Go API     │                       │ Astro frontend  │
              │  :8080      │                       │ :4321           │
              └──────┬──────┘                       │ dev server or   │
                     │                              │ static build    │
                     ▼                              └─────────────────┘
              ┌─────────────┐
              │ PostgreSQL  │  TLS (DB_SSLMODE=require)
              │ :5432       │
              └─────────────┘
```

In development, Compose mounts the source trees and runs the Astro dev server plus the Go backend under [`air`](https://github.com/air-verse/air) for live reload. In production, the frontend is built to static files served by its own Nginx container, and the backend is compiled to a static binary.

## Tech stack

| Layer | Technology |
| --- | --- |
| Backend | Go 1.26 (`net/http`, `lib/pq`, `golang-jwt/jwt`, `golang.org/x/crypto`) |
| Frontend | Astro 4, TypeScript, Web Crypto API, vendored `marked` + DOMPurify |
| Database | PostgreSQL 15 |
| Proxy | Nginx (TLS termination, rate limiting, security headers) |
| Runtime | Docker Compose |
| CI | GitHub Actions |

The backend uses only the Go standard library and a small set of dependencies; there is no web framework or ORM.

## Security model and limitations

### What the encryption does

1. During registration, the browser generates an X25519 key pair. The public key is stored on the server; the PKCS#8 private key is encrypted with a key derived from the account password using PBKDF2-SHA256 (100,000 iterations, 16-byte salt, 12-byte AES-GCM IV) and stored as a salt + IV + ciphertext blob.
2. At login, the browser decrypts the wrapped private key with the password and keeps it in `sessionStorage`. The public key is kept in `localStorage`.
3. To send, the client fetches the recipient's public key, performs X25519 ECDH, derives a 256-bit message key with HKDF-SHA256 (salt = SHA-256 of the sorted public keys, info = `message-encryption` + the server-provided E2EE pepper), and encrypts the payload with AES-256-GCM and a random nonce.
4. The server stores the JSON envelope (`encrypted`, `ciphertext`, `nonce`) and the sender's public key so the recipient can derive the same message key and decrypt locally.
5. Attachments are embedded in the encrypted JSON payload rather than uploaded separately.

### Server-side protections

| Item | Implementation |
| --- | --- |
| Passwords | Argon2id (64 MiB, 3 iterations, parallelism 2) with a server pepper |
| JWT | HS256, one-hour expiry, secret must be at least 32 characters |
| TOTP secrets | AES-256-GCM with a key derived from `ENCRYPTION_SECRET` via HKDF-SHA256 |
| Password reset tokens | 32 random bytes, SHA-256 hashed in the database, one-hour expiry, single use |
| Database transport | TLS with `DB_SSLMODE=require` |
| Account lockout | 1 failure → 1 min, 3+ → 5 min, 5 → permanent block (cleared by password reset) |
| Rate limiting | Nginx: 10 r/s API, 5/min login, 3/min register; Go: 100/min general, 10/min auth routes |
| CSRF | Random token per user, 15-minute expiry, required on selected write endpoints |

### Limitations

This is the honest fine print:

- **No formal protocol or audit.** The primitives are standard, but the composition is a prototype. A production messenger should use a reviewed protocol such as the Signal Double Ratchet, with forward secrecy and post-compromise security.
- **The server is trusted for key discovery.** Public keys are not signed, pinned, or backed by key transparency. A malicious server could substitute a public key. Fingerprints allow manual comparison but are not enforced by the UI.
- **Plaintext fallback exists.** If the client cannot initialize E2EE, the dashboard logs a warning and can send an unencrypted JSON payload. The backend rejects messages to recipients without a public key but does not reject a sender whose session private key is missing. Do not describe this implementation as "always encrypted."
- **`E2EE_PEPPER` is not a client secret.** It is served to authenticated clients at `/api/e2ee/config`. Treat it as domain separation, not as an additional secret protecting messages.
- **Password reset does not re-wrap the E2EE private key.** The reset flow changes the password hash but leaves the old wrapped key untouched. After a reset, the private key cannot be unwrapped with the new password, so E2EE stops working for that account until its keys are manually rotated or a new account is created. There is no key-rotation UI; the `update-public-key` endpoint also updates only the public key, so calling it without re-wrapping the matching private key makes new messages undecryptable.
- **JWTs live in `localStorage`.** This is convenient but exposed to XSS; the CSP and input sanitization reduce, but do not eliminate, that risk. There is no refresh token or server-side revocation list.
- **In-memory state resets on restart.** CSRF tokens and Go-side rate-limit counters are per-process. The Nginx limits provide a second layer.
- **Attachments are inlined.** Base64 inflates size by roughly a third, and large payloads are held in memory. The current caps are 15 MB per file and 25 MB per message.
- **Self-signed certificates are for development.** Compose generates a localhost certificate on first run. The database container also uses a self-signed certificate with `sslmode=require`, which encrypts the connection but does not verify the CA.
- **No account-management console.** The settings page includes login history and a honeypot statistics panel, but the latter is admin-gated by setting `is_admin = TRUE` directly in the database.

## Project layout

```text
.
├── docker-compose.yml          Development stack (hot reload, mounted source)
├── docker-compose.prod.yml     Production stack (compiled binaries, static frontend)
├── .env.example                Environment template
├── go-backend/
│   ├── main.go                 Routes, auth middleware, rate limiters, startup
│   ├── handlers/               Auth, messages, E2EE, TOTP, reset, monitoring
│   ├── cryptography/           Argon2id hashing and AES-256-GCM helpers
│   ├── totp/                   RFC 6238 implementation
│   ├── jwt_auth/               JWT issuance and validation
│   ├── csrf/                   In-memory CSRF token store
│   ├── validation/             Input validation and login-attempt tracking
│   ├── password_utils/         Strength scoring and common-password checks
│   ├── password_reset/         Reset-token generation and hashing
│   ├── login_monitoring/       Login history and device fingerprinting
│   ├── honeypot/               Honeypot recording and statistics
│   ├── middleware/             CORS and per-IP rate limiting
│   ├── email/                  SMTP notifications
│   └── 100k-most-used-passwords-NCSC.txt
├── frontend/
│   ├── src/pages/              index, login, register, reset-password,
│   │                           dashboard, settings
│   ├── src/layouts/            BaseLayout.astro
│   ├── src/lib/                api, crypto, e2ee, dom helpers
│   ├── src/scripts/            Per-page client scripts
│   ├── src/styles/             Shared theme, base, auth, and app styles
│   ├── public/vendor/          Vendored marked and DOMPurify
│   ├── Dockerfile              Astro dev server
│   └── Dockerfile.prod         Static build served by Nginx
├── nginx/
│   ├── nginx.conf              Main Nginx configuration
│   ├── conf.d/default.conf     TLS, upstreams, rate limits, security headers
│   └── ssl/                    TLS certificates (real certs are gitignored)
├── sql-database/
│   ├── init.sql                Schema and indexes, applied on first start
│   ├── init-ssl.sh             Enables TLS in PostgreSQL
│   └── Dockerfile              PostgreSQL 15 with TLS setup
├── scripts/
│   ├── test_honeypots.sh       Honeypot smoke tests (bash)
│   └── test_honeypots.ps1      Honeypot smoke tests (PowerShell)
└── .github/workflows/ci.yml    Lint, test, build, Docker image checks
```

## Getting started

### Prerequisites

- Docker Engine with the Compose plugin
- For running pieces outside containers: Go 1.26.1+ and Node.js 20 + pnpm 9

### 1. Configure the environment

```sh
cp .env.example .env
```

Edit `.env` and replace every placeholder:

- Use at least 32 characters for `PEPPER`, `E2EE_PEPPER`, `ENCRYPTION_SECRET`, and `JWT_SECRET`. Generate independent random values, for example:

  ```sh
  openssl rand -base64 48
  ```

- Set `DB_PASSWORD` to a strong value and keep `DB_USER` / `DB_NAME` consistent with the Compose defaults (or update both).
- Fill in `SMTP_*` to enable password reset emails and new-device alerts. Messaging still works without valid SMTP, but those features will fail and log errors.
- Optionally set `FRONTEND_URL` (used to build password-reset links, default `http://localhost:4321`) and `ALLOWED_ORIGINS` (comma-separated CORS allow-list).

`.env` is git-ignored. Never commit real secrets. If a secret changes after data exists, existing password hashes, wrapped TOTP secrets, or E2EE data may become unreadable.

### 2. Start the development stack

```sh
docker compose up --build
```

Open <https://localhost:8443>. The first request uses a self-signed certificate, so accept the browser warning. Plain HTTP on port 8000 redirects to HTTPS, except for `/health`.

What is running:

| Service | Port | Notes |
| --- | --- | --- |
| Nginx | 8000, 8443 | Entry point; generates a dev certificate if missing |
| Frontend | 4321 (internal) | Astro dev server with hot reload |
| Backend | 8080 (internal) | Go API with `air` live reload |
| PostgreSQL | 5432 (internal) | Data persists in the `postgres_data` volume |

### 3. Try it out

1. Register two accounts. Registration generates an X25519 key pair and wraps the private key with the password.
2. Use two browser profiles (or a normal and a private window) so each account has its own stored public key and session key.
3. Send a message with and without an attachment. Decryption happens in the browser; the database only contains the JSON ciphertext envelope.
4. Open **Settings** to enable 2FA and inspect login history.

To see the admin-only honeypot statistics, promote an account manually:

```sh
docker compose exec database sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

Then run:

```sql
UPDATE Users SET is_admin = TRUE WHERE email = 'you@example.com';
```

Reload the settings page afterwards.

### Reset local data

```sh
docker compose down -v
docker compose up --build
```

The `-v` flag removes the PostgreSQL volume, including all users and messages. Schema changes in `sql-database/init.sql` only apply to a fresh database; existing volumes are not migrated automatically.

## Configuration reference

| Variable | Required | Default / notes |
| --- | --- | --- |
| `PEPPER` | Yes | Server-side pepper for password hashing; at least 32 characters |
| `E2EE_PEPPER` | Yes | Input to client key derivation, served to authenticated clients via `/api/e2ee/config` |
| `ENCRYPTION_SECRET` | Yes | Master secret for encrypting TOTP secrets at rest; at least 32 characters |
| `JWT_SECRET` | Yes | HS256 signing key; startup fails below 32 characters |
| `DB_HOST` | Yes | `database` in Compose |
| `DB_PORT` | Yes | `5432` |
| `DB_USER` | Yes | PostgreSQL user |
| `DB_PASSWORD` | Yes | PostgreSQL password |
| `DB_NAME` | Yes | Database name |
| `DB_SSLMODE` | No | Set to `require` by both Compose files; backend defaults to `require` |
| `SMTP_ADDR` | For email | SMTP host and port, e.g. `smtp.example.com:587` |
| `SMTP_HOST` | For email | Used for SMTP authentication and TLS server name fallback |
| `SMTP_USER` | For email | SMTP username |
| `SMTP_PASS` | For email | SMTP password or API key |
| `SMTP_TLS_SERVER_NAME` | No | TLS server name; defaults to `SMTP_HOST` |
| `SMTP_FROM_EMAIL` | For email | Sender address |
| `SMTP_FROM_NAME` | No | Sender display name; defaults to `Komunikator` |
| `FRONTEND_URL` | No | Base URL for password-reset links; defaults to `http://localhost:4321`. Set it to the public HTTPS origin in production. |
| `ALLOWED_ORIGINS` | No | Comma-separated CORS origins; defaults to `http://localhost:3000,http://localhost:4321` |

Startup fails fast if any of the four secrets is missing; `JWT_SECRET` must also be at least 32 characters.

## API overview

All `/api/*` endpoints return JSON. Authenticated endpoints expect:

```http
Authorization: Bearer <JWT>
Content-Type: application/json
```

Errors use the shape `{"message": "..."}` with an appropriate HTTP status. State-changing endpoints marked with **CSRF** also require a token from `GET /api/csrf-token` in the request body as `csrf_token`.

### Public endpoints

| Method | Path | Description |
| --- | --- | --- |
| POST | `/api/register` | Create an account with E2EE public key and wrapped private key |
| POST | `/api/login` | Password login; may return `requires_totp: true` |
| POST | `/api/2fa/validate` | Complete a login that requires TOTP |
| POST | `/api/check-password-strength` | Score a password for the live meter |
| POST | `/api/password-reset/request` | Request a reset email (always returns a generic response) |
| POST | `/api/password-reset/verify` | Consume a reset token and set a new password |

### Authenticated endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/csrf-token` | Issue a CSRF token valid for 15 minutes |
| GET | `/api/2fa/status` | Whether 2FA is enabled or setup is in progress |
| POST | `/api/2fa/setup` | Generate a TOTP secret (CSRF) |
| POST | `/api/2fa/verify` | Confirm the first TOTP code and enable 2FA (CSRF) |
| POST | `/api/2fa/disable` | Disable 2FA after confirming a code (CSRF) |
| GET | `/api/messages` | Inbox, paginated with `?page=` and `?limit=` (max 100) |
| POST | `/api/messages/send` | Send an encrypted message (CSRF) |
| GET | `/api/messages/sent` | Sent messages, paginated |
| GET | `/api/messages/get?id=` | Fetch a single accessible message |
| PUT | `/api/messages/mark-read` | Mark an inbox message as read |
| DELETE | `/api/messages/delete` | Soft-delete a message for the current user |
| GET | `/api/e2ee/keys` | Own public key and wrapped private key |
| GET | `/api/e2ee/config` | E2EE client configuration (`pepper`) |
| GET | `/api/e2ee/fingerprint` | Own public-key fingerprint (SHA-256 hex) |
| GET | `/api/user/public-key?email=` | Look up a peer's public key |
| GET | `/api/user/fingerprint?email=` | Look up a peer's fingerprint |
| POST | `/api/user/update-public-key` | Rotate the stored public key (CSRF) |
| GET | `/api/login-history` | Last 20 login attempts for the current user |
| GET | `/api/admin/honeypot-stats` | Honeypot statistics for the last 30 days (admin only) |

`GET /health` is available on both Nginx listeners and does not require authentication.

## Data model

The schema lives in [`sql-database/init.sql`](sql-database/init.sql) and creates:

| Table | Purpose |
| --- | --- |
| `Users` | Account credentials, E2EE keys, TOTP state, lockout/block status, admin flag |
| `Messages` | Ciphertext envelope, sender/receiver keys, read state, per-side deletion |
| `PasswordResetTokens` | Hashed reset tokens with expiry and single-use tracking |
| `LoginHistory` | Successful and failed logins, IP, user agent, device fingerprint, new-device flag |
| `HoneypotAttempts` | Triggered honeypot fields, submitted metadata, IP, and block status |

Useful indexes cover unread inbox queries, sender/receiver lookups, reset-token expiry, login history by user/IP/time, honeypot attempts by IP/time, and TOTP-enabled users.

## Development and testing

### Backend

```sh
cd go-backend
go test ./...
go vet ./...
gofmt -l .        # should print nothing
go build ./...
```

Tests are co-located with packages and use `go-sqlmock` for database-facing code.

### Frontend

```sh
cd frontend
pnpm install --frozen-lockfile
pnpm build
pnpm dev          # only useful together with the backend and database
```

### Full stack

```sh
docker compose up --build
```

Handy commands while the stack is running:

```sh
docker compose ps                 # service status
docker compose logs -f backend    # follow backend logs
docker compose logs -f frontend   # follow Astro logs
docker compose config             # render the resolved Compose config
```

### Production build

1. Put real certificates at `nginx/ssl/cert.pem` and `nginx/ssl/key.pem` (see [`nginx/ssl/README.md`](nginx/ssl/README.md)). The production Compose file mounts `nginx/ssl` read-only and does not generate certificates.
2. Use fresh, strong secrets in `.env` and do not reuse development values.
3. Build and start:

   ```sh
   docker compose -f docker-compose.prod.yml up --build -d
   ```

   The production stack compiles the backend binary with `CGO_ENABLED=0`, builds the frontend to static assets, and drops source bind mounts.

### CI

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs on pushes and pull requests to `main`:

- `go vet` and `gofmt` checks
- `go test -v -count=1 ./...`
- `go build ./...`
- Frontend install (`--frozen-lockfile`) and build
- Docker image builds for the backend, backend prod, frontend, frontend prod, and database images

### Honeypot smoke scripts

```sh
./scripts/test_honeypots.sh [BASE_URL]
VERBOSE=1 ./scripts/test_honeypots.sh
LONG_DELAY=1 ./scripts/test_honeypots.sh   # slower, avoids tripping rate limits
```

There is a PowerShell equivalent at `scripts/test_honeypots.ps1` with `-BaseUrl`. The scripts default to `http://localhost:8000`; point them at an HTTPS base URL only if your shell trusts the certificate, and expect `429` responses when running the suite quickly.

## Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| Browser warns about the certificate | Expected with the generated self-signed dev certificate. Accept it, or install a trusted local certificate under `nginx/ssl`. |
| "E2EE not available" after login | The private key is in `sessionStorage` and is lost on tab close/logout. Log in again. If keys are missing entirely, there is no recovery or key-rotation UI; you need to generate a new key pair and store it manually or create a new account. A browser without X25519 Web Crypto support cannot use E2EE. |
| E2EE stopped working after a password reset | The reset changes the password hash but not the password-wrapped private key. The existing wrapped key cannot be decrypted with the new password, so keys must be rotated manually or a new account used. |
| Message cannot be decrypted | The sender's public key stored with the message does not match the one used to encrypt, or the message predates key rotation. Fingerprints should be compared out of band before trusting a new key. |
| `401` on every API call | The JWT expired (one hour). Log in again. |
| `429 Too Many Requests` | Nginx and Go rate limits are active. Wait, or use `LONG_DELAY=1` with the honeypot scripts. |
| Login says the account is locked or blocked | Failed attempts trigger a 1-minute lock, a 5-minute lock, then a permanent block. A successful password reset clears the block. |
| Password reset email never arrives | Check `SMTP_*`, `FRONTEND_URL`, and the backend logs. The API intentionally returns the same response whether or not the address exists. |
| Database authentication fails after changing `.env` | The volume was initialized with the old credentials. Run `docker compose down -v` to recreate it (this deletes all data). |
| Schema changes do not appear | `init.sql` runs only on an empty data directory. Reset the volume or apply migrations manually. |
| Ports 8000 or 8443 already in use | Stop the conflicting service or edit the port mappings in the Compose file. |
| Backend crashes on startup | Ensure all four secrets are set and `JWT_SECRET` is at least 32 characters. The process validates these before serving traffic. |

## License

This repository does not currently include a license file. Add one before distributing or reusing the code.
