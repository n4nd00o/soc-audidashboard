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

issue_api_cert() {
    # Build "--host H" pairs from the comma-separated list (no globbing, no word surprises).
    set -f
    old_ifs=$IFS
    IFS=,
    set --
    for host in $API_HOSTS; do
        set -- "$@" --host "$host"
    done
    IFS=$old_ifs
    set +f
    audidash-server issue-server-cert "$@" \
        --out-cert "$SHARED_DIR/api.crt" --out-key "$SHARED_DIR/api.key"
}

if [ ! -f "$SHARED_DIR/api.crt" ] || [ ! -f "$SHARED_DIR/api.key" ]; then
    echo "entrypoint: issuing the API listener certificate for: $API_HOSTS"
    rm -f "$SHARED_DIR/api.crt" "$SHARED_DIR/api.key"
    issue_api_cert
fi

# Caddy trusts client certificates signed by this CA (client_auth trust_pool).
cp "$DATA_DIR/ca/ca.crt" "$SHARED_DIR/ca.crt.tmp"
mv -f "$SHARED_DIR/ca.crt.tmp" "$SHARED_DIR/ca.crt"

exec "$@"
