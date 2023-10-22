#!/usr/bin/env bash

# If SOURCE_COMMIT is provided via env skip this
if [ -z "${SOURCE_COMMIT+x}" ]; then
    SOURCE_COMMIT="$(git rev-parse HEAD)"
fi

# If VW_VERSION is provided via env use it as SOURCE_VERSION
# Else define it using git
if [[ -n "${VW_VERSION}" ]]; then
    SOURCE_VERSION="${VW_VERSION}"
else
    GIT_EXACT_TAG="$(git describe --tags --abbrev=0 --exact-match 2>/dev/null)"
    if [[ -n "${GIT_EXACT_TAG}" ]]; then
        SOURCE_VERSION="${GIT_EXACT_TAG}"
    else
        GIT_LAST_TAG="$(git describe --tags --abbrev=0)"
        SOURCE_VERSION="${GIT_LAST_TAG}-${SOURCE_COMMIT:0:8}"
        GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
        case "${GIT_BRANCH}" in
            main|master|HEAD)
                # Do not add the branch name for these branches
                ;;
            *)
                SOURCE_VERSION="${SOURCE_VERSION} (${GIT_BRANCH})"
                ;;
        esac
    fi
fi

# Export the rendered variables above so bake will use them
export SOURCE_COMMIT
export SOURCE_VERSION
