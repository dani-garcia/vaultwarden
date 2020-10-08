# The default Debian-based images support these arches for all database connections
#
# Other images (Alpine-based) currently
# support only a subset of these.
arches=(
    amd64
    arm32v6
    arm32v7
    arm64v8
)

if [[ "${DOCKER_TAG}" == *alpine ]]; then
    # The Alpine build currently only works for amd64.
    os_suffix=.alpine
    arches=(
        amd64
        arm32v7
    )
fi
