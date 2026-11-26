#!/bin/sh
# Container entrypoint for the AudiDashboard server.
# Prepares the database, the internal CA and the files shared with Caddy, then runs "$@".
# Never prints secrets: only file paths and the CA fingerprint (public) are shown.
set -eu

DATA_DIR="${AUDIDASH_DATA_DIR:-/data}"
SHARED_DIR="${DATA_DIR}/proxy"
API_HOSTS="${AUDIDASH_API_HOSTS:-localhost,127.0.0.1}"

echo "entrypoint: applying database migrations"
python -c 'import os; from audidash_server.db import run_migrations; run_migrations(os.environ["AUDIDASH_DATABASE_URL"])'

echo "entrypoint: ensuring the internal CA exists"
audidash-server init-ca

mkdir -p "$SHARED_DIR"

with_api_hosts() {
    # Run "$@" plus one "--host H" pair per comma-separated entry of AUDIDASH_API_HOSTS
    # (globbing disabled, so entries are passed through verbatim to the CLI's validation).
    set -f
    old_ifs=$IFS
    IFS=,
    for host in $API_HOSTS; do
        set -- "$@" --host "$host"
    done
    IFS=$old_ifs
    set +f
    "$@"
}

# Keep the existing certificate only if it chains to the current CA, is valid for at least
# 30 more days and its SAN set equals AUDIDASH_API_HOSTS; otherwise issue a new one.
if [ -f "$SHARED_DIR/api.key" ] && with_api_hosts audidash-server check-server-cert \
    --cert "$SHARED_DIR/api.crt" --min-days 30; then
    echo "entrypoint: API listener certificate is current"
else
    echo "entrypoint: issuing the API listener certificate for: $API_HOSTS"
    rm -f "$SHARED_DIR/api.crt" "$SHARED_DIR/api.key"
    with_api_hosts audidash-server issue-server-cert \
        --out-cert "$SHARED_DIR/api.crt" --out-key "$SHARED_DIR/api.key"
fi

# Caddy trusts client certificates signed by this CA (client_auth trust_pool).
cp "$DATA_DIR/ca/ca.crt" "$SHARED_DIR/ca.crt.tmp"
mv -f "$SHARED_DIR/ca.crt.tmp" "$SHARED_DIR/ca.crt"

exec "$@"
