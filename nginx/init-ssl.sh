#!/bin/sh
set -e

# Create directories if missing
mkdir -p /etc/letsencrypt/live/default
mkdir -p /var/www/certbot

# If a real Let's Encrypt certificate exists for a domain, link default to it
for d in /etc/letsencrypt/live/*; do
    if [ -d "$d" ] && [ "$(basename "$d")" != "default" ] && [ -f "$d/fullchain.pem" ]; then
        echo "Found valid Let's Encrypt certificate in $d, linking to default..."
        rm -rf /etc/letsencrypt/live/default
        ln -sf "$d" /etc/letsencrypt/live/default
        break
    fi
done

# If no certificate exists, create a self-signed placeholder certificate so Nginx can start
if [ ! -f /etc/letsencrypt/live/default/fullchain.pem ]; then
    echo "Creating self-signed placeholder certificate for initial startup..."
    mkdir -p /etc/letsencrypt/live/default
    openssl req -x509 -nodes -newkey rsa:2048 -days 30 \
        -keyout /etc/letsencrypt/live/default/privkey.pem \
        -out /etc/letsencrypt/live/default/fullchain.pem \
        -subj "/CN=enterprise-ids-ips-soc"
fi

echo "SSL initialization complete. Starting Nginx..."
exec nginx -g "daemon off;"
