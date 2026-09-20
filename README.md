# Projekt Komunikator

A small end-to-end encrypted messaging prototype: a Go backend, an Astro frontend, PostgreSQL, and an Nginx reverse proxy, all wired up with Docker Compose.

Messages are end-to-end encrypted in the browser (X25519 + HKDF + AES-256-GCM via the Web Crypto API); the server only ever stores ciphertext. Attachments are carried inside the encrypted message payload.

## Features

- **E2EE messaging** — client-side key agreement and AES-256-GCM encryption; private keys are wrapped with the user's password (PBKDF2) and never sent in the clear.
- **Encrypted attachments** — files are embedded in the encrypted message payload.
- **Authentication** — JWT-based sessions.
- **2FA** — TOTP (RFC 6238).
- **Password security** — Argon2id hashing, a common-password blocklist (NCSC 100k), and a real-time strength meter.
- **Security hardening** — CSRF tokens, honeypot fields, failed-login lockout/blocking, per-IP rate limiting, CORS allow-list, CSP and other security headers.
- **Account monitoring** — login history and honeypot statistics in the settings UI.

## Tech stack

- **Backend**: Go (`net/http`, `lib/pq`, `golang-jwt`, `golang.org/x/crypto`)
- **Frontend**: Astro + TypeScript (Web Crypto API)
- **Database**: PostgreSQL
- **Proxy**: Nginx (TLS, rate limiting, security headers)
- **Runtime**: Docker / Docker Compose

## Project layout

```
go-backend/            Go API server
  main.go              routes, middleware wiring, rate limiters
  handlers/            HTTP handlers and request/response helpers
  cryptography/        Argon2id hashing and AES-256-GCM key wrapping
  totp/                TOTP implementation
  jwt_auth/            JWT issuance and validation
  csrf/                in-memory CSRF token store
  validation/          input validation and login-attempt tracking
  password_utils/      password strength and common-password checks
  password_reset/      reset-token generation and hashing
  login_monitoring/    login history and device fingerprinting
  honeypot/            honeypot event recording and stats
  middleware/          CORS, rate limiting
  email/               SMTP notifications
frontend/              Astro app
  src/pages/           index, login, register, reset-password, dashboard, settings
  src/layouts/         BaseLayout.astro
  src/lib/             shared client modules (api, crypto, e2ee, dom)
  src/scripts/         per-page client scripts
  src/styles/          shared stylesheets (auth, app)
  public/vendor/       vendored marked + DOMPurify
nginx/                 reverse-proxy config and TLS cert setup
sql-database/          schema (init.sql) and DB image
scripts/               honeypot smoke-test scripts
```

## Getting started

### Prerequisites

- Docker and Docker Compose
- For running pieces outside Docker: Go 1.26+, Node 20 + pnpm 9

### Configure

```sh
cp .env.example .env
```

Then edit `.env`. `JWT_SECRET` must be at least 32 characters; set `PEPPER` and `ENCRYPTION_SECRET` to random values and fill in the `DB_*` / `SMTP_*` settings. `.env` is git-ignored — never commit real secrets.

### Run (development)

```sh
docker compose up --build
```

The app is served at <https://localhost:8443> (plain HTTP on port 8000 redirects to HTTPS). With a self-signed certificate you will need to accept the browser warning. The stack includes the frontend dev server (with hot reload), the Go backend with live reload (`air`), PostgreSQL, and Nginx.

### Run (production)

Provide real certificates at `nginx/ssl/cert.pem` and `nginx/ssl/key.pem` (see `nginx/ssl/README.md`), then:

```sh
docker compose -f docker-compose.prod.yml up --build
```

This builds the optimized frontend image (static build served by Nginx) and the compiled backend binary.

### Tests

```sh
cd go-backend
go test ./...
```

CI additionally runs `gofmt`, `go vet`, the frontend build, and Docker image builds for both prod targets.

## API overview

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/api/register` | Create an account (with E2EE keys) |
| POST | `/api/login` | Password login |
| POST | `/api/2fa/validate` | Complete a 2FA login |
| POST | `/api/check-password-strength` | Strength analysis for the meter |
| GET | `/api/csrf-token` | Issue a CSRF token (auth) |
| GET/POST | `/api/2fa/status`, `/setup`, `/verify`, `/disable` | Manage TOTP 2FA (auth) |
| GET/POST | `/api/messages`, `/send`, `/sent`, `/get`, `/mark-read`, `/delete` | Messaging (auth) |
| GET | `/api/e2ee/keys`, `/config`, `/fingerprint` | E2EE key and fingerprint data (auth) |
| GET | `/api/user/public-key`, `/fingerprint` | Peer key lookup (auth) |
| POST | `/api/user/update-public-key` | Rotate your public key (auth) |
| POST | `/api/password-reset/request`, `/verify` | Password reset flow |
| GET | `/api/login-history`, `/api/admin/honeypot-stats` | Account/admin monitoring (auth) |

## Crypto notes

- **Password hashing**: Argon2id (`go-backend/cryptography/cryptography.go`).
- **Server-side secret wrapping**: AES-256-GCM with HKDF-derived keys, used for TOTP secrets (`go-backend/cryptography/encryption.go`).
- **TOTP**: RFC 6238 (`go-backend/totp`).
- **Client-side E2EE**: X25519 ECDH → HKDF-SHA256 → AES-256-GCM; the private key is wrapped with PBKDF2-SHA256 (100k iterations) using the user's password (`frontend/src/lib/crypto.ts`, `frontend/src/lib/e2ee.ts`).

This repository is a prototype. The crypto is composed from standard primitives, but for production use a reviewed, complete protocol (e.g. libsodium-style vetted constructions or the Signal Double Ratchet) is recommended.
