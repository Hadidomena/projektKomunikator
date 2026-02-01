#!/bin/bash
# Initialize SSL configuration for PostgreSQL
# This runs during database initialization when postgres user has proper permissions

# Wait for PostgreSQL data directory to be initialized
while [ ! -f /var/lib/postgresql/data/postgresql.conf ]; do
    sleep 1
done

# Check if SSL certificates already exist
if [ ! -f /var/lib/postgresql/ssl/server.crt ]; then
    echo "Generating SSL certificates for PostgreSQL..."
    
    # Generate self-signed certificate for development
    openssl req -new -x509 -days 365 -nodes -text \
        -out /var/lib/postgresql/ssl/server.crt \
        -keyout /var/lib/postgresql/ssl/server.key \
        -subj "/CN=postgres-server" 2>/dev/null || true
    
    # Set proper permissions if certificates were created
    if [ -f /var/lib/postgresql/ssl/server.key ]; then
        chmod 600 /var/lib/postgresql/ssl/server.key
        chown postgres:postgres /var/lib/postgresql/ssl/server.key /var/lib/postgresql/ssl/server.crt
        echo "SSL certificates generated successfully"
    fi
fi

# Configure PostgreSQL to use SSL
if [ -f /var/lib/postgresql/ssl/server.crt ] && [ -f /var/lib/postgresql/ssl/server.key ]; then
    echo "ssl = on" >> /var/lib/postgresql/data/postgresql.conf
    echo "ssl_cert_file = '/var/lib/postgresql/ssl/server.crt'" >> /var/lib/postgresql/data/postgresql.conf
    echo "ssl_key_file = '/var/lib/postgresql/ssl/server.key'" >> /var/lib/postgresql/data/postgresql.conf
    echo "SSL enabled in PostgreSQL configuration"
fi

