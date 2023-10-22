#!/usr/bin/env bash

# Determine the basedir of this script.
# It should be located in the same directory as the docker-bake.hcl
# This ensures you can run this script from both inside and outside of the docker directory
BASEDIR=$(RL=$(readlink -n "$0"); SP="${RL:-$0}"; dirname "$(cd "$(dirname "${SP}")" || exit; pwd)/$(basename "${SP}")")

# Load build env's
source "${BASEDIR}/bake_env.sh"

# Be verbose on what is being executed
set -x

# Make sure we set the context to `..` so it will go up one directory
docker buildx bake --progress plain --set "*.context=${BASEDIR}/.." -f "${BASEDIR}/docker-bake.hcl" "$@"
