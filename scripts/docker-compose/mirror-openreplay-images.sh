#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  mirror-openreplay-images.sh <target-registry> [tag]

Examples:
  ./mirror-openreplay-images.sh ghcr.io/my-org/openreplay v1.23.0
  ./mirror-openreplay-images.sh registry.example.com/openreplay v1.23.0

Set SOURCE_REGISTRY to override the upstream source registry.
Default source: public.ecr.aws/p1t3u8a3

Set PLATFORM to override the Docker fallback platform.
Default platform: linux/amd64

The target registry must already exist and Docker must be logged in if it
requires authentication.
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

retry() {
  local attempt=1
  local max_attempts=5
  local delay=10

  until "$@"; do
    if (( attempt >= max_attempts )); then
      echo "Command failed after ${max_attempts} attempts: $*" >&2
      return 1
    fi
    echo "Retry ${attempt}/${max_attempts} after ${delay}s: $*" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

target_registry="${1:-}"
tag="${2:-v1.23.0}"
source_registry="${SOURCE_REGISTRY:-public.ecr.aws/p1t3u8a3}"
platform="${PLATFORM:-linux/amd64}"

if [[ -z "$target_registry" ]]; then
  usage
  exit 1
fi

target_registry="${target_registry%/}"
source_registry="${source_registry%/}"

require_cmd docker

images=(
  alerts
  api
  http
  images
  integrations
  sink
  sourcemapreader
  spot
  storage
  assets
  assist
  canvases
  chalice
  db
  ender
  frontend
  heuristics
)

for image in "${images[@]}"; do
  source_image="${source_registry}/${image}:${tag}"
  target_image="${target_registry}/${image}:${tag}"
  echo "Mirroring ${source_image} -> ${target_image}"

  if command -v skopeo >/dev/null 2>&1; then
    retry skopeo copy --all "docker://${source_image}" "docker://${target_image}"
  else
    retry docker pull --platform "$platform" "$source_image"
    docker tag "$source_image" "$target_image"
    retry docker push "$target_image"
  fi
done

echo
echo "Mirror complete. Set this in Dokploy:"
echo "COMMON_APP_IMAGE_REGISTRY=${target_registry}"
