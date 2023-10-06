#!/usr/bin/env sh

# Determine the basedir of this script.
# It should be located in the same directory as the docker-bake.hcl
# This ensures you can run this script from both inside and outside of the docker directory
BASEDIR=$(RL=$(readlink -n "$0"); SP="${RL:-$0}"; dirname "$(cd "$(dirname "${SP}")" || exit; pwd)/$(basename "${SP}")")

if [ -z "${SOURCE_COMMIT}" ]; then
    SOURCE_COMMIT="$(git rev-parse HEAD)"
fi

GIT_EXACT_TAG="$(git describe --tags --abbrev=0 --exact-match 2>/dev/null)"
if [ -n "${GIT_EXACT_TAG}" ]; then
    SOURCE_VERSION="${GIT_EXACT_TAG}"
else
    GIT_LAST_TAG="$(git describe --tags --abbrev=0)"
    SOURCE_VERSION="${GIT_LAST_TAG}-$(printf '%s' "${SOURCE_COMMIT}" | cut -c 8)"
fi

# Export the rendered variables above so bake will use them
export SOURCE_COMMIT
export SOURCE_VERSION

# Make sure we set the context to `..` so it will go up one directory
docker buildx bake --progress plain --set "*.context=${BASEDIR}/.." -f "${BASEDIR}/docker-bake.hcl" "$@"
