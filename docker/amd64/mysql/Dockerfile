# This file was generated using a Jinja2 template.
# Please make your changes in `Dockerfile.j2` and then `make` the individual Dockerfile's.

# Using multistage build:
# 	https://docs.docker.com/develop/develop-images/multistage-build/
# 	https://whitfin.io/speeding-up-rust-docker-builds/
####################### VAULT BUILD IMAGE  #######################

#  This hash is extracted from the docker web-vault builds and it's prefered over a simple tag because it's immutable.
#  It can be viewed in multiple ways:
#  - From the https://hub.docker.com/repository/docker/bitwardenrs/web-vault/tags page, click the tag name and the digest should be there.
#  - From the console, with the following commands:
#      docker pull bitwardenrs/web-vault:v2.14.0
#      docker image inspect --format "{{.RepoDigests}}" bitwardenrs/web-vault:v2.14.0
#
#  - To do the opposite, and get the tag from the hash, you can do:
#      docker image inspect --format "{{.RepoTags}}" bitwardenrs/web-vault@sha256:c62e0b8698562e03fe2759374f3ecd760d9612e4eaf0af4583f231ebf05d6df5
FROM bitwardenrs/web-vault@sha256:c62e0b8698562e03fe2759374f3ecd760d9612e4eaf0af4583f231ebf05d6df5 as vault

########################## BUILD IMAGE  ##########################
# We need to use the Rust build image, because
# we need the Rust compiler and Cargo tooling
FROM rust:1.40 as build

# set mysql backend
ARG DB=mysql

# Build time options to avoid dpkg warnings and help with reproducible builds.
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 TZ=UTC TERM=xterm-256color

# Don't download rust docs
RUN rustup set profile minimal

# Install MySQL package
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    libmariadb-dev \
    && rm -rf /var/lib/apt/lists/*

# Creates a dummy project used to grab dependencies
RUN USER=root cargo new --bin /app
WORKDIR /app

# Copies over *only* your manifests and build files
COPY ./Cargo.* ./
COPY ./rust-toolchain ./rust-toolchain
COPY ./build.rs ./build.rs

# Builds your dependencies and removes the
# dummy project, except the target folder
# This folder contains the compiled dependencies
RUN cargo build --features ${DB} --release
RUN find . -not -path "./target*" -delete

# Copies the complete project
# To avoid copying unneeded files, use .dockerignore
COPY . .

# Make sure that we actually build the project
RUN touch src/main.rs

# Builds again, this time it'll just be
# your actual source files being built
RUN cargo build --features ${DB} --release

######################## RUNTIME IMAGE  ########################
# Create a new stage with a minimal image
# because we already have a binary built
FROM debian:buster-slim

ENV ROCKET_ENV "staging"
ENV ROCKET_PORT=80
ENV ROCKET_WORKERS=10

# Install needed libraries
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    openssl \
    ca-certificates \
    curl \
    libmariadbclient-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /data
VOLUME /data
EXPOSE 80
EXPOSE 3012

# Copies the files from the context (Rocket.toml file and web-vault)
# and the binary from the "build" stage to the current stage
COPY Rocket.toml .
COPY --from=vault /web-vault ./web-vault
COPY --from=build app/target/release/bitwarden_rs .

COPY docker/healthcheck.sh /healthcheck.sh

HEALTHCHECK --interval=60s --timeout=10s CMD ["/healthcheck.sh"]

# Configures the startup!
WORKDIR /
CMD ["/bitwarden_rs"]
