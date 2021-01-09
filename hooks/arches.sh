# The default Debian-based images support these arches for all database backends.
arches=(
    amd64
    armv6
    armv7
    arm64
)

if [[ "${DOCKER_TAG}" == *alpine ]]; then
    # The Alpine image build currently only works for certain arches.
    distro_suffix=.alpine
    arches=(
        amd64
        armv7
    )
fi
