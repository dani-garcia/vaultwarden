# The default Debian-based SQLite images support these arches.
#
# Other images (Alpine-based, or with other database backends) currently
# support only a subset of these.
arches=(
    amd64
    arm32v6
    arm32v7
    arm64v8
)

case "${DOCKER_REPO}" in
    *-mysql)
        db=mysql
        arches=(amd64)
        ;;
    *-postgresql)
        db=postgresql
        arches=(amd64)
        ;;
    *)
        db=sqlite
        ;;
esac

if [[ "${DOCKER_TAG}" == *alpine ]]; then
    # The Alpine build currently only works for amd64.
    os_suffix=.alpine
    arches=(amd64)
fi
