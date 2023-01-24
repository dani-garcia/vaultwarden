# syntax=docker/dockerfile:1

# This file was generated using a Jinja2 template.
# Please make your changes in `Dockerfile.j2` and then `make` the individual Dockerfiles.

# Using multistage build:
# 	https://docs.docker.com/develop/develop-images/multistage-build/
# 	https://whitfin.io/speeding-up-rust-docker-builds/
####################### VAULT BUILD IMAGE  #######################
# The web-vault digest specifies a particular web-vault build on Docker Hub.
# Using the digest instead of the tag name provides better security,
# as the digest of an image is immutable, whereas a tag name can later
# be changed to point to a malicious image.
#
# To verify the current digest for a given tag name:
# - From https://hub.docker.com/r/vaultwarden/web-vault/tags,
#   click the tag name to view the digest of the image it currently points to.
# - From the command line:
#     $ docker pull vaultwarden/web-vault:v2023.1.1
#     $ docker image inspect --format "{{.RepoDigests}}" vaultwarden/web-vault:v2023.1.1
#     [vaultwarden/web-vault@sha256:d5f71fb05c4b87935bf51d84140db0f8716cabfe2974fbee6c0c5ee8cf7dab5a]
#
# - Conversely, to get the tag name from the digest:
#     $ docker image inspect --format "{{.RepoTags}}" vaultwarden/web-vault@sha256:d5f71fb05c4b87935bf51d84140db0f8716cabfe2974fbee6c0c5ee8cf7dab5a
#     [vaultwarden/web-vault:v2023.1.1]
#
FROM vaultwarden/web-vault@sha256:d5f71fb05c4b87935bf51d84140db0f8716cabfe2974fbee6c0c5ee8cf7dab5a as vault

########################## BUILD IMAGE  ##########################
FROM rust:1.66-bullseye as build



# Build time options to avoid dpkg warnings and help with reproducible builds.
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TZ=UTC \
    TERM=xterm-256color \
    CARGO_HOME="/root/.cargo" \
    USER="root"


# Create CARGO_HOME folder and don't download rust docs
RUN mkdir -pv "${CARGO_HOME}" \
    && rustup set profile minimal

# Install DB packages
RUN apt-get update \
    && apt-get install -y \
        --no-install-recommends \
        libmariadb-dev \
        libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Creates a dummy project used to grab dependencies
RUN USER=root cargo new --bin /app
WORKDIR /app

# Copies over *only* your manifests and build files
COPY ./Cargo.* ./
COPY ./rust-toolchain ./rust-toolchain
COPY ./build.rs ./build.rs


# Configure the DB ARG as late as possible to not invalidate the cached layers above
ARG DB=sqlite,mysql,postgresql

# Builds your dependencies and removes the
# dummy project, except the target folder
# This folder contains the compiled dependencies
RUN cargo build --features ${DB} --release \
    && find . -not -path "./target*" -delete

# Copies the complete project
# To avoid copying unneeded files, use .dockerignore
COPY . .

# Make sure that we actually build the project
RUN touch src/main.rs

# Builds again, this time it'll just be
# your actual source files being built
# hadolint ignore=DL3059
RUN cargo build --features ${DB} --release

######################## RUNTIME IMAGE  ########################
# Create a new stage with a minimal image
# because we already have a binary built
FROM debian:bullseye-slim

ENV ROCKET_PROFILE="release" \
    ROCKET_ADDRESS=0.0.0.0 \
    ROCKET_PORT=80


# Create data folder and Install needed libraries
RUN mkdir /data \
    && apt-get update && apt-get install -y \
    --no-install-recommends \
    openssl \
    ca-certificates \
    curl \
    libmariadb-dev-compat \
    libpq5 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


VOLUME /data
EXPOSE 80
EXPOSE 3012

# Copies the files from the context (Rocket.toml file and web-vault)
# and the binary from the "build" stage to the current stage
WORKDIR /
COPY --from=vault /web-vault ./web-vault
COPY --from=build /app/target/release/vaultwarden .

COPY docker/healthcheck.sh /healthcheck.sh
COPY docker/start.sh /start.sh

HEALTHCHECK --interval=60s --timeout=10s CMD ["/healthcheck.sh"]

CMD ["/start.sh"]
