#!/usr/bin/env bash
set -euo pipefail

db="${1:-}"
schema_root="${SCHEMA_ROOT:-/opt/openreplay/openreplay/scripts/schema}"
from_version="${OPENREPLAY_FROM_VERSION:-}"
to_version="${OPENREPLAY_TO_VERSION:-${COMMON_VERSION:-v1.27.0}}"

usage() {
  echo "Usage: $0 <postgresql|clickhouse>" >&2
}

version_key() {
  local version="${1#v}"
  awk -F. -v version="$version" 'BEGIN {
    split(version, parts, ".")
    printf "%03d%03d%03d", parts[1], parts[2], parts[3]
  }'
}

migration_versions() {
  local db_name="$1"
  local db_dir="$schema_root/db/init_dbs/$db_name"
  local from_key
  local to_key

  from_key="$(version_key "$from_version")"
  to_key="$(version_key "$to_version")"

  find "$db_dir" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; \
    | grep -v '^create$' \
    | while read -r version; do
        key="$(version_key "$version")"
        if [[ "$key" > "$from_key" ]] && [[ "$key" < "$to_key" || "$key" == "$to_key" ]]; then
          printf '%s %s\n' "$key" "$version"
        fi
      done \
    | sort \
    | awk 'BEGIN { sep = "" } { printf "%s%s", sep, $2; sep = "," }'
}

if [[ -z "$db" ]]; then
  usage
  exit 1
fi

case "$db" in
postgresql)
  helper="/tmp/postgresql.sh"
  ;;
clickhouse)
  helper="/tmp/clickhouse.sh"
  ;;
*)
  usage
  exit 1
  ;;
esac

if [[ -z "$from_version" ]]; then
  echo "OPENREPLAY_FROM_VERSION is not set; initializing $db if needed."
  exec bash "$helper" init
fi

versions="$(migration_versions "$db")"
if [[ -z "$versions" ]]; then
  echo "No $db migrations needed from $from_version to $to_version."
  exit 0
fi

echo "Migrating $db from $from_version to $to_version with versions: $versions"
exec bash "$helper" migrate "$versions"
