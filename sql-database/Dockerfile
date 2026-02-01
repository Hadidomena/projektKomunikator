# Use the official PostgreSQL image
FROM postgres:15-alpine

# Install OpenSSL for certificate generation
RUN apk add --no-cache openssl bash

# Create SSL directory and generate certificates during build
RUN mkdir -p /var/lib/postgresql/ssl && \
    openssl req -new -x509 -days 365 -nodes -text \
        -out /var/lib/postgresql/ssl/server.crt \
        -keyout /var/lib/postgresql/ssl/server.key \
        -subj "/CN=postgres-server" && \
    chmod 600 /var/lib/postgresql/ssl/server.key && \
    chown -R postgres:postgres /var/lib/postgresql/ssl

# Copy SSL initialization script
COPY init-ssl.sh /docker-entrypoint-initdb.d/00-init-ssl.sh
RUN chmod +x /docker-entrypoint-initdb.d/00-init-ssl.sh

# You can specify user, password, and database name using environment variables
# when running the container (e.g., with docker-compose).
# Example environment variables:
# ENV POSTGRES_USER=user
# ENV POSTGRES_PASSWORD=password
# ENV POSTGRES_DB=communicator_db

# Expose the default PostgreSQL port
EXPOSE 5432
