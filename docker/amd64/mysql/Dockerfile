# Using multistage build: 
# 	https://docs.docker.com/develop/develop-images/multistage-build/
# 	https://whitfin.io/speeding-up-rust-docker-builds/
####################### VAULT BUILD IMAGE  #######################
FROM alpine:3.10 as vault

ENV VAULT_VERSION "v2.12.0"

ENV URL "https://github.com/dani-garcia/bw_web_builds/releases/download/$VAULT_VERSION/bw_web_$VAULT_VERSION.tar.gz"

RUN apk add --no-cache --upgrade \
    curl \
    tar

RUN mkdir /web-vault
WORKDIR /web-vault

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

RUN curl -L $URL | tar xz
RUN ls

########################## BUILD IMAGE  ##########################
# We need to use the Rust build image, because
# we need the Rust compiler and Cargo tooling
FROM rust:1.36 as build

# set mysql backend
ARG DB=mysql

# Using bundled SQLite, no need to install it
# RUN apt-get update && apt-get install -y\
#    --no-install-recommends \
#    sqlite3\
# && rm -rf /var/lib/apt/lists/*

# Install MySQL package
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    libmariadb-dev \
    && rm -rf /var/lib/apt/lists/*

# Creates a dummy project used to grab dependencies
RUN USER=root cargo new --bin app
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
FROM debian:stretch-slim

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

COPY docker/healthcheck.sh ./healthcheck.sh

HEALTHCHECK --interval=10s --timeout=1s CMD sh healthcheck.sh || exit 1

# Configures the startup!
CMD ["./bitwarden_rs"]