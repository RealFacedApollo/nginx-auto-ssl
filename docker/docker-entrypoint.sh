#!/bin/sh
# Entrypoint: optional token-from-env and server-block templating for fleets.
# Mounting your own /etc/nginx/conf.d/*.conf and secret files skips both.
set -eu

: "${CERTMATE_API_TOKEN_FILE:=/run/secrets/certmate_token}"

# Allow CERTMATE_API_TOKEN env as an alternative to a mounted secret file.
if [ -n "${CERTMATE_API_TOKEN:-}" ]; then
    printf '%s' "$CERTMATE_API_TOKEN" > "$CERTMATE_API_TOKEN_FILE"
    chmod 600 "$CERTMATE_API_TOKEN_FILE"
fi

# Generate server blocks from CERTMATE_DOMAINS when no config is mounted.
if ! ls /etc/nginx/conf.d/*.conf >/dev/null 2>&1; then
    if [ -n "${CERTMATE_DOMAINS:-}" ] && [ -n "${CERTMATE_URL:-}" ]; then
        {
            echo "certmate_url ${CERTMATE_URL};"
            echo "certmate_api_token_file ${CERTMATE_API_TOKEN_FILE};"
            for d in $CERTMATE_DOMAINS; do
                cat <<SERVER
server {
    listen 443 ssl;
    ssl_certificate_from_certmate ${d};
    location / {
        return 200 'ok\n';
    }
}
SERVER
            done
        } > /etc/nginx/conf.d/auto-ssl.conf
    else
        echo "error: no /etc/nginx/conf.d/*.conf and CERTMATE_URL/CERTMATE_DOMAINS unset" >&2
        echo "mount server config or set CERTMATE_URL, CERTMATE_DOMAINS, and a token" >&2
        exit 1
    fi
fi

exec "$@"
