# TLS certificates

**These files are examples for local development ONLY.**

- `cert.pem.example` / `key.pem.example` — a self-signed certificate for `localhost`
  checked into the repository as a reference. The private key is NOT a secret of
  any real deployment, but committing private keys is still bad practice.

- `cert.pem` / `key.pem` — your actual local certificate. These are **gitignored**
  and should never be committed.

## Generate your own dev certs

```sh
./generate-certs.sh
```

`docker compose up` also generates them automatically if they are missing.

## Production

Do **not** use these certificates in production. Obtain a trusted certificate
(e.g. from Let's Encrypt via certbot) and mount it at `/etc/nginx/ssl/cert.pem`
and `/etc/nginx/ssl/key.pem`.
