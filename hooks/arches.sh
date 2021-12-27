# The default Debian-based images support these arches for all database backends.
arches=(
    amd64
    armv6
    armv7
    arm64
)

if [[ "${DOCKER_TAG}" == *alpine ]]; then
    distro_suffix=.alpine
fi
