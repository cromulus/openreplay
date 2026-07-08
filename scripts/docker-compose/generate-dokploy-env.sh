#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  generate-dokploy-env.sh <domain> [output-file]

Examples:
  ./generate-dokploy-env.sh openreplay.example.com
  ./generate-dokploy-env.sh openreplay.example.com dokploy.env

The output is a Dokploy/Compose environment block for dokploy.docker-compose.yml.
EOF
}

rand_hex() {
  openssl rand -hex "$1"
}

kafka_cluster_id() {
  openssl rand -base64 16 | tr '+/' '-_' | tr -d '='
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

require_cmd openssl
require_cmd tr

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

domain="${1:-}"
output_file="${2:-}"

if [[ -z "$domain" ]]; then
  usage
  exit 1
fi

protocol="https"
case "$domain" in
  http://*)
    protocol="http"
    domain="${domain#http://}"
    ;;
  https://*)
    protocol="https"
    domain="${domain#https://}"
    ;;
esac
domain="${domain%%/*}"

if [[ -z "$domain" ]]; then
  echo "Domain cannot be empty." >&2
  exit 1
fi

env_block="$(cat <<EOF
COMMON_VERSION=v1.23.0
COMMON_APP_IMAGE_REGISTRY=public.ecr.aws/p1t3u8a3
COMMON_PROTOCOL=${protocol}
COMMON_DOMAIN_NAME=${domain}
COMMON_JWT_SECRET=$(rand_hex 32)
COMMON_JWT_SPOT_SECRET=$(rand_hex 32)
COMMON_JWT_REFRESH_SECRET=$(rand_hex 32)
COMMON_JWT_SPOT_REFRESH_SECRET=$(rand_hex 32)
COMMON_ASSIST_JWT_SECRET=$(rand_hex 32)
COMMON_ASSIST_KEY=$(rand_hex 32)
COMMON_TOKEN_SECRET=$(rand_hex 32)
COMMON_KAFKA_CLUSTER_ID=$(kafka_cluster_id)
COMMON_S3_KEY=$(rand_hex 10)
COMMON_S3_SECRET=$(rand_hex 32)
COMMON_PG_PASSWORD=$(rand_hex 24)
POSTGRES_VERSION=17
REDIS_VERSION=8
RUSTFS_VERSION=1.0.0-beta.1
CLICKHOUSE_VERSION=25.11-alpine
KAFKA_VERSION=3
EOF
)"

if [[ -n "$output_file" ]]; then
  umask 077
  printf '%s\n' "$env_block" >"$output_file"
  echo "Wrote $output_file" >&2
else
  printf '%s\n' "$env_block"
fi
