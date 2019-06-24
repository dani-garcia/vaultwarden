# Using multistage build: 
# 	https://docs.docker.com/develop/develop-images/multistage-build/
# 	https://whitfin.io/speeding-up-rust-docker-builds/
####################### VAULT BUILD IMAGE  #######################
FROM alpine as vault

ENV VAULT_VERSION "v2.10.1"

ENV URL "https://github.com/dani-garcia/bw_web_builds/releases/download/$VAULT_VERSION/bw_web_$VAULT_VERSION.tar.gz"

RUN apk add --update-cache --upgrade \
    curl \
    tar

RUN mkdir /web-vault
WORKDIR /web-vault

RUN curl -L $URL | tar xz
RUN ls

########################## BUILD IMAGE  ##########################
# We need to use the Rust build image, because
# we need the Rust compiler and Cargo tooling
FROM rust as build

# set sqlite as default for DB ARG for backward comaptibility
ARG DB=sqlite

# Using bundled SQLite, no need to install it
# RUN apt-get update && apt-get install -y\
#    sqlite3\
#    --no-install-recommends\
# && rm -rf /var/lib/apt/lists/*

# Install MySQL package
RUN apt-get update && apt-get install -y \
    libmariadb-dev\
    --no-install-recommends\
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
RUN apt-get update && apt-get install -y\
    openssl\
    ca-certificates\
    libmariadbclient-dev\
    --no-install-recommends\
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

# Configures the startup!
CMD ./bitwarden_rs
