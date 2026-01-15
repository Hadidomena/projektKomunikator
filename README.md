Projekt Komunikator
===================

Short description
- **Project**: A small end-to-end encrypted messaging prototype with a Go backend and Astro frontend.
- **Authentication**: JWT-based authentication with secure token management (see [JWT_AUTHENTICATION.md](JWT_AUTHENTICATION.md))
- **Password Security**: Real-time password strength indicator with comprehensive analysis (see [PASSWORD_STRENGTH.md](PASSWORD_STRENGTH.md))
- **E2EE**: Multi-device End-to-End Encryption with X25519/AES-256-GCM (see [E2EE_IMPLEMENTATION.md](E2EE_IMPLEMENTATION.md))

Where to look
- **Backend crypto**: `go-backend/cryptography`
- **E2EE management**: `go-backend/e2ee`
- **Message encryption**: `go-backend/message_utils`
- **Password checks**: `go-backend/password_utils`
- **JWT authentication**: `go-backend/jwt_auth`
- **Input validation**: `go-backend/validation`
- **Registration UI**: `frontend/src/pages/register.astro`

Documentation
- [JWT Authentication Guide](JWT_AUTHENTICATION.md) - Token-based authentication
- [Password Strength Guide](PASSWORD_STRENGTH.md) - Password validation and UI
- [E2EE Implementation](E2EE_IMPLEMENTATION.md) - Server-side E2EE architecture
- [E2EE Client Guide](E2EE_CLIENT_GUIDE.md) - JavaScript/TypeScript client examples

Implemented algorithms
- **Argon2id (password hashing)**: used for secure, memory-hard password hashing (`go-backend/cryptography/cryptography.go`).
- **X25519 (ECDH)**: performs ephemeral Elliptic-Curve Diffie–Hellman key agreement to compute shared secrets (`go-backend/cryptography/keys.go`).
- **HKDF**: extracts and expands keys from the ECDH shared secret to produce root/chain keys (`go-backend/cryptography/keys.go`).
- **HMAC-based KDF**: HMAC (with the chosen hash function) is used to derive message and chain keys in the symmetric ratchet (`go-backend/cryptography/keys.go`).
- **AES-256-GCM**: authenticated symmetric encryption for messages (AES-GCM, message keys expected to be 32 bytes) (`go-backend/message_utils/message_utils.go`).
- **Shannon entropy (estimator)**: used in password strength calculation (`go-backend/password_utils/password_utils.go`).
- **Base64 encoding/decoding**: used across modules for key and ciphertext serialization.

Notes
- This repository contains a number of crypto building blocks (ECDH, HKDF, ratchet-style key derivation, AES-GCM). Treat this code as a prototype — for production use, a reviewed, complete protocol implementation (e.g., Signal Double Ratchet or libsodium-style vetted primitives) is recommended.
