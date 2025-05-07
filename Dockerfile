# syntax=docker/dockerfile:1
# check=skip=FromPlatformFlagConstDisallowed,RedundantTargetPlatform

# This file was generated using a Jinja2 template.
# Please make your changes in `DockerSettings.yaml` or `Dockerfile.j2` and then `make`
# This will generate two Dockerfile's `Dockerfile.debian` and `Dockerfile.alpine`

# Using multistage build:
# 	https://docs.docker.com/develop/develop-images/multistage-build/
# 	https://whitfin.io/speeding-up-rust-docker-builds/

####################### VAULT BUILD IMAGE #######################
# The web-vault digest specifies a particular web-vault build on Docker Hub.
# Using the digest instead of the tag name provides better security,
# as the digest of an image is immutable, whereas a tag name can later
# be changed to point to a malicious image.
#
# To verify the current digest for a given tag name:
# - From https://hub.docker.com/r/vaultwarden/web-vault/tags,
#   click the tag name to view the digest of the image it currently points to.
# - From the command line:
#     $ docker pull docker.io/vaultwarden/web-vault:v2025.3.1
#     $ docker image inspect --format "{{.RepoDigests}}" docker.io/vaultwarden/web-vault:v2025.3.1
#     [docker.io/vaultwarden/web-vault@sha256:5b11739052c26dc3c2135b28dc5b072bc607f870a3e81fbbcc72e0cd1f124bcd]
#
# - Conversely, to get the tag name from the digest:
#     $ docker image inspect --format "{{.RepoTags}}" docker.io/vaultwarden/web-vault@sha256:5b11739052c26dc3c2135b28dc5b072bc607f870a3e81fbbcc72e0cd1f124bcd
#     [docker.io/vaultwarden/web-vault:v2025.3.1]
#
FROM --platform=linux/amd64 docker.io/vaultwarden/web-vault@sha256:5b11739052c26dc3c2135b28dc5b072bc607f870a3e81fbbcc72e0cd1f124bcd AS vault

########################## Cross Compile Docker Helper Scripts ##########################
## We use the linux/amd64 no matter which Build Platform, since these are all bash scripts
## And these bash scripts do not have any significant difference if at all
FROM --platform=linux/amd64 docker.io/tonistiigi/xx@sha256:9c207bead753dda9430bdd15425c6518fc7a03d866103c516a2c6889188f5894 AS xx

########################## BUILD IMAGE ##########################
# hadolint ignore=DL3006
FROM --platform=$BUILDPLATFORM docker.io/library/rust:1.86.0-slim-bookworm AS build
COPY --from=xx / /
ARG TARGETARCH
ARG TARGETVARIANT
ARG TARGETPLATFORM

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Build time options to avoid dpkg warnings and help with reproducible builds.
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TZ=UTC \
    TERM=xterm-256color \
    CARGO_HOME="/root/.cargo" \
    USER="root"

# Install clang to get `xx-cargo` working
# Install pkg-config to allow amd64 builds to find all libraries
# Install git so build.rs can determine the correct version
# Install the libc cross packages based upon the debian-arch
RUN apt-get update && \
    apt-get install -y \
        --no-install-recommends \
        clang \
        pkg-config \
        git \
        "libc6-$(xx-info debian-arch)-cross" \
        "libc6-dev-$(xx-info debian-arch)-cross" \
        "linux-libc-dev-$(xx-info debian-arch)-cross" && \
    xx-apt-get install -y \
        --no-install-recommends \
        gcc \
        libmariadb3 \
        libpq-dev \
        libpq5 \
        libssl-dev \
        zlib1g-dev && \
    # Force install arch dependend mariadb dev packages
    # Installing them the normal way breaks several other packages (again)
    apt-get download "libmariadb-dev-compat:$(xx-info debian-arch)" "libmariadb-dev:$(xx-info debian-arch)" && \
    dpkg --force-all -i ./libmariadb-dev*.deb && \
    # Run xx-cargo early, since it sometimes seems to break when run at a later stage
    echo "export CARGO_TARGET=$(xx-cargo --print-target-triple)" >> /env-cargo

# Create CARGO_HOME folder and don't download rust docs
RUN mkdir -pv "${CARGO_HOME}" && \
    rustup set profile minimal

# Creates a dummy project used to grab dependencies
RUN USER=root cargo new --bin /app
WORKDIR /app

# Environment variables for Cargo on Debian based builds
ARG TARGET_PKG_CONFIG_PATH

RUN source /env-cargo && \
    if xx-info is-cross ; then \
        # We can't use xx-cargo since that uses clang, which doesn't work for our libraries.
        # Because of this we generate the needed environment variables here which we can load in the needed steps.
        echo "export CC_$(echo "${CARGO_TARGET}" | tr '[:upper:]' '[:lower:]' | tr - _)=/usr/bin/$(xx-info)-gcc" >> /env-cargo && \
        echo "export CARGO_TARGET_$(echo "${CARGO_TARGET}" | tr '[:lower:]' '[:upper:]' | tr - _)_LINKER=/usr/bin/$(xx-info)-gcc" >> /env-cargo && \
        echo "export CROSS_COMPILE=1" >> /env-cargo && \
        echo "export PKG_CONFIG_ALLOW_CROSS=1" >> /env-cargo && \
        # For some architectures `xx-info` returns a triple which doesn't matches the path on disk
        # In those cases you can override this by setting the `TARGET_PKG_CONFIG_PATH` build-arg
        if [[ -n "${TARGET_PKG_CONFIG_PATH}" ]]; then \
            echo "export TARGET_PKG_CONFIG_PATH=${TARGET_PKG_CONFIG_PATH}" >> /env-cargo ; \
        else \
            echo "export PKG_CONFIG_PATH=/usr/lib/$(xx-info)/pkgconfig" >> /env-cargo ; \
        fi && \
        echo "# End of env-cargo" >> /env-cargo ; \
    fi && \
    # Output the current contents of the file
    cat /env-cargo

RUN source /env-cargo && \
    rustup target add "${CARGO_TARGET}"

# Copies over *only* your manifests and build files
COPY ./Cargo.* ./rust-toolchain.toml ./build.rs ./
COPY ./macros ./macros

ARG CARGO_PROFILE=release

# Configure the DB ARG as late as possible to not invalidate the cached layers above
ARG DB=sqlite,mysql,postgresql

# Builds your dependencies and removes the
# dummy project, except the target folder
# This folder contains the compiled dependencies
RUN source /env-cargo && \
    cargo build --features ${DB} --profile "${CARGO_PROFILE}" --target="${CARGO_TARGET}" && \
    find . -not -path "./target*" -delete

# Copies the complete project
# To avoid copying unneeded files, use .dockerignore
COPY . .

ARG VW_VERSION

# Builds again, this time it will be the actual source files being build
RUN source /env-cargo && \
    # Make sure that we actually build the project by updating the src/main.rs timestamp
    # Also do this for build.rs to ensure the version is rechecked
    touch build.rs src/main.rs && \
    # Create a symlink to the binary target folder to easy copy the binary in the final stage
    cargo build --features ${DB} --profile "${CARGO_PROFILE}" --target="${CARGO_TARGET}" && \
    if [[ "${CARGO_PROFILE}" == "dev" ]] ; then \
        ln -vfsr "/app/target/${CARGO_TARGET}/debug" /app/target/final ; \
    else \
        ln -vfsr "/app/target/${CARGO_TARGET}/${CARGO_PROFILE}" /app/target/final ; \
    fi


######################## RUNTIME IMAGE  ########################
# Create a new stage with a minimal image
# because we already have a binary built
#
# To build these images you need to have qemu binfmt support.
# See the following pages to help install these tools locally
# Ubuntu/Debian: https://wiki.debian.org/QemuUserEmulation
# Arch Linux: https://wiki.archlinux.org/title/QEMU#Chrooting_into_arm/arm64_environment_from_x86_64
#
# Or use a Docker image which modifies your host system to support this.
# The GitHub Actions Workflow uses the same image as used below.
# See: https://github.com/tonistiigi/binfmt
# Usage: docker run --privileged --rm tonistiigi/binfmt --install arm64,arm
# To uninstall: docker run --privileged --rm tonistiigi/binfmt --uninstall 'qemu-*'
#
# We need to add `--platform` here, because of a podman bug: https://github.com/containers/buildah/issues/4742
FROM --platform=$TARGETPLATFORM docker.io/library/debian:bookworm-slim

ENV ROCKET_PROFILE="release" \
    ROCKET_ADDRESS=0.0.0.0 \
    ROCKET_PORT=80 \
    DEBIAN_FRONTEND=noninteractive

# Create data folder and Install needed libraries
RUN mkdir /data && \
    apt-get update && apt-get install -y \
        --no-install-recommends \
        ca-certificates \
        curl \
        libmariadb-dev-compat \
        libpq5 \
        openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

VOLUME /data
EXPOSE 80

# Copies the files from the context (Rocket.toml file and web-vault)
# and the binary from the "build" stage to the current stage
WORKDIR /

COPY docker/healthcheck.sh docker/start.sh /

COPY --from=vault /web-vault ./web-vault
COPY --from=build /app/target/final/vaultwarden .

HEALTHCHECK --interval=60s --timeout=10s CMD ["/healthcheck.sh"]

CMD ["/start.sh"]
