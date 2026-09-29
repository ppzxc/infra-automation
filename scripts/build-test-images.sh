#!/usr/bin/env bash
# ==============================================================================
# Build the molecule Test Images (molecule/images/*.Dockerfile) when missing or
# when their Dockerfile changed. Staleness is detected by comparing a sha256 of
# the Dockerfile with the label baked into the existing image, so an unchanged
# image is never rebuilt. FORCE=1 rebuilds regardless (e.g. to pick up a newer
# upstream base image).
#   usage: build-test-images.sh [rockylinux8 rockylinux9 ubuntu2204 ...]
# ==============================================================================
set -eo pipefail

cd "$(dirname "$0")/.."
IMAGES=("$@")
[ ${#IMAGES[@]} -eq 0 ] && IMAGES=(rockylinux8 rockylinux9 ubuntu2204)

for name in "${IMAGES[@]}"; do
    file="molecule/images/${name}.Dockerfile"
    tag="infra-test-${name}:local"
    [ -f "$file" ] || { echo "[✗] $file not found"; exit 1; }
    sha="$(sha256sum "$file" | cut -d' ' -f1)"
    current="$(docker image inspect --format '{{ index .Config.Labels "infra.dockerfile.sha" }}' "$tag" 2>/dev/null || true)"
    if [ "${FORCE:-0}" != "1" ] && [ "$current" = "$sha" ]; then
        echo "[i] $tag up to date"
        continue
    fi
    echo "[i] Building $tag"
    docker build --quiet --build-arg "DOCKERFILE_SHA=$sha" -t "$tag" -f "$file" molecule/images >/dev/null
done
