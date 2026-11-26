#!/bin/sh
# Container entrypoint for the AudiDashboard server.
# Prepares the database, the internal CA and the files shared with Caddy, then runs "$@".
# Never prints secrets: only file paths and the CA fingerprint (public) are shown.
set -eu

DATA_DIR="${AUDIDASH_DATA_DIR:-/data}"
SHARED_DIR="${DATA_DIR}/proxy"
API_HOSTS="${AUDIDASH_API_HOSTS:-localhost,127.0.0.1}"
DASHBOARD_HOSTS="${AUDIDASH_DASHBOARD_HOSTS:-localhost,127.0.0.1}"

echo "entrypoint: applying database migrations"
python -c 'import os; from audidash_server.db import run_migrations; run_migrations(os.environ["AUDIDASH_DATABASE_URL"])'

echo "entrypoint: ensuring the internal CA exists"
audidash-server init-ca

mkdir -p "$SHARED_DIR"

with_hosts() {
    # with_hosts HOSTS CMD...: run CMD plus one "--host H" pair per comma-separated entry of
    # HOSTS (globbing disabled, so entries are passed through verbatim to the CLI's validation).
    hosts=$1
    shift
    set -f
    old_ifs=$IFS
    IFS=,
    for host in $hosts; do
        set -- "$@" --host "$host"
    done
    IFS=$old_ifs
    set +f
    "$@"
}

ensure_server_cert() {
    # ensure_server_cert NAME HOSTS: keep $SHARED_DIR/NAME.crt only if it chains to the current
    # CA, is valid for at least 30 more days and its SAN set equals HOSTS; otherwise reissue.
    name=$1
    hosts=$2
    if [ -f "$SHARED_DIR/$name.key" ] && with_hosts "$hosts" audidash-server check-server-cert \
        --cert "$SHARED_DIR/$name.crt" --min-days 30; then
        echo "entrypoint: $name listener certificate is current"
    else
        echo "entrypoint: issuing the $name listener certificate for: $hosts"
        rm -f "$SHARED_DIR/$name.crt" "$SHARED_DIR/$name.key"
        with_hosts "$hosts" audidash-server issue-server-cert \
            --out-cert "$SHARED_DIR/$name.crt" --out-key "$SHARED_DIR/$name.key"
    fi
}

# :9443 (device API, mTLS) and :8443 (dashboard + /enroll) both present certificates issued
# by the internal CA, so `audidash enroll --ca-fingerprint` can verify the dashboard listener
# before sending the enrolment token.
ensure_server_cert api "$API_HOSTS"
ensure_server_cert dashboard "$DASHBOARD_HOSTS"

# Caddy trusts client certificates signed by this CA (client_auth trust_pool); operators copy
# it for `curl --cacert` checks.
cp "$DATA_DIR/ca/ca.crt" "$SHARED_DIR/ca.crt.tmp"
mv -f "$SHARED_DIR/ca.crt.tmp" "$SHARED_DIR/ca.crt"

exec "$@"
