#!/usr/bin/env bash

# Determine the basedir of this script.
# It should be located in the same directory as the docker-bake.hcl
# This ensures you can run this script from both inside and outside of the docker directory
BASEDIR=$(RL=$(readlink -n "$0"); SP="${RL:-$0}"; dirname "$(cd "$(dirname "${SP}")" || exit; pwd)/$(basename "${SP}")")

# Load build env's
source "${BASEDIR}/bake_env.sh"

# Check if a target is given as first argument
# If not we assume the defaults and pass the given arguments to the podman command
case "${1}" in
    alpine*|debian*)
        TARGET="${1}"
        # Now shift the $@ array so we only have the rest of the arguments
        # This allows us too append these as extra arguments too the podman buildx build command
        shift
    ;;
esac

LABEL_ARGS=(
    --label org.opencontainers.image.description="Unofficial Bitwarden compatible server written in Rust"
    --label org.opencontainers.image.licenses="AGPL-3.0-only"
    --label org.opencontainers.image.documentation="https://github.com/vaultwarden/vaultwarden/wiki"
    --label org.opencontainers.image.url="https://github.com/vaultwarden/vaultwarden"
    --label org.opencontainers.image.created="$(date --utc --iso-8601=seconds)"
)
if [[ -n "${SOURCE_REPOSITORY_URL}" ]]; then
    LABEL_ARGS+=(--label org.opencontainers.image.source="${SOURCE_REPOSITORY_URL}")
fi
if [[ -n "${SOURCE_COMMIT}" ]]; then
    LABEL_ARGS+=(--label org.opencontainers.image.revision="${SOURCE_COMMIT}")
fi
if [[ -n "${SOURCE_VERSION}" ]]; then
    LABEL_ARGS+=(--label org.opencontainers.image.version="${SOURCE_VERSION}")
fi

# Check if and which --build-arg arguments we need to configure
BUILD_ARGS=()
if [[ -n "${DB}" ]]; then
    BUILD_ARGS+=(--build-arg DB="${DB}")
fi
if [[ -n "${CARGO_PROFILE}" ]]; then
    BUILD_ARGS+=(--build-arg CARGO_PROFILE="${CARGO_PROFILE}")
fi
if [[ -n "${VW_VERSION}" ]]; then
    BUILD_ARGS+=(--build-arg VW_VERSION="${VW_VERSION}")
fi

# Set the default BASE_TAGS if non are provided
if [[ -z "${BASE_TAGS}" ]]; then
    BASE_TAGS="testing"
fi

# Set the default CONTAINER_REGISTRIES if non are provided
if [[ -z "${CONTAINER_REGISTRIES}" ]]; then
    CONTAINER_REGISTRIES="vaultwarden/server"
fi

# Check which Dockerfile we need to use, default is debian
case "${TARGET}" in
    alpine*)
        BASE_TAGS="${BASE_TAGS}-alpine"
        DOCKERFILE="Dockerfile.alpine"
        ;;
    *)
        DOCKERFILE="Dockerfile.debian"
        ;;
esac

# Check which platform we need to build and append the BASE_TAGS with the architecture
case "${TARGET}" in
    *-arm64)
        BASE_TAGS="${BASE_TAGS}-arm64"
        PLATFORM="linux/arm64"
        ;;
    *-armv7)
        BASE_TAGS="${BASE_TAGS}-armv7"
        PLATFORM="linux/arm/v7"
        ;;
    *-armv6)
        BASE_TAGS="${BASE_TAGS}-armv6"
        PLATFORM="linux/arm/v6"
        ;;
    *)
        BASE_TAGS="${BASE_TAGS}-amd64"
        PLATFORM="linux/amd64"
        ;;
esac

# Be verbose on what is being executed
set -x

# Build the image with podman
# We use the docker format here since we are using `SHELL`, which is not supported by OCI
# shellcheck disable=SC2086
podman buildx build \
  --platform="${PLATFORM}" \
  --tag="${CONTAINER_REGISTRIES}:${BASE_TAGS}" \
  --format=docker \
  "${LABEL_ARGS[@]}" \
  "${BUILD_ARGS[@]}" \
  --file="${BASEDIR}/${DOCKERFILE}" "$@" \
  "${BASEDIR}/.."
