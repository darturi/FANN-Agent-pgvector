#!/bin/sh
set -eu

if [ "$#" -eq 0 ] || [ "$(id -u)" != 0 ]; then
    echo "secured copy requires its root bootstrap wrapper" >&2
    exit 1
fi

# This runs before postgres, including on container restart. Never continue on error.
if [ "$1" = "--copy-proxy" ]; then
    if [ "$#" -ne 2 ]; then exit 1; fi
    case "$2" in *[!0-9.]*|"") exit 1 ;; esac
    database="$2"
    policy=/usr/local/share/fannagent/proxy.nft
    table=fannagent_proxy
    render_policy() { sed "s/@DATABASE_IP@/$database/g" "$policy"; }
    set -- socat TCP4-LISTEN:5432,reuseaddr,fork TCP4:"$database":5432
elif [ "$1" = "postgres" ]; then
    policy=/usr/local/share/fannagent/copy.nft
    table=fannagent_copy
    render_policy() { cat "$policy"; }
else
    echo "unsupported secured copy command" >&2
    exit 1
fi
render_policy | nft --check --file -
if nft list table inet "$table" >/dev/null 2>&1; then
    nft delete table inet "$table"
fi
render_policy | nft --file -

exec setpriv --reuid=postgres --regid=postgres --init-groups \
    --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    --no-new-privs "$@"
