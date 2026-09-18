#!/bin/sh
# Generates a self-signed certificate for local development.
# These files are NOT for production use.
# Real certificates should come from a trusted CA (e.g. Let's Encrypt).

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"

openssl req -x509 -newkey rsa:2048 -sha256 \
    -nodes \
    -keyout "$DIR/key.pem" \
    -out "$DIR/cert.pem" \
    -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Generated $DIR/cert.pem and $DIR/key.pem"
echo "These are self-signed DEVELOPMENT certificates. Do NOT use in production."
