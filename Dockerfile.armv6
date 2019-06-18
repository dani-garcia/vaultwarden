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

RUN apt-get update \
    && apt-get install -y \
        gcc-arm-linux-gnueabi \
    && mkdir -p ~/.cargo \
    && echo '[target.arm-unknown-linux-gnueabi]' >> ~/.cargo/config \
    && echo 'linker = "arm-linux-gnueabi-gcc"' >> ~/.cargo/config

ENV CARGO_HOME "/root/.cargo"
ENV USER "root"

WORKDIR /app

# Prepare openssl armel libs
RUN sed 's/^deb/deb-src/' /etc/apt/sources.list > \
        /etc/apt/sources.list.d/deb-src.list \
    && dpkg --add-architecture armel \
    && apt-get update \
    && apt-get install -y \
        libssl-dev:armel \
        libc6-dev:armel \
        libmariadb-dev:armel

ENV CC_arm_unknown_linux_gnueabi="/usr/bin/arm-linux-gnueabi-gcc"
ENV CROSS_COMPILE="1"
ENV OPENSSL_INCLUDE_DIR="/usr/include/arm-linux-gnueabi"
ENV OPENSSL_LIB_DIR="/usr/lib/arm-linux-gnueabi"

# Copies the complete project
# To avoid copying unneeded files, use .dockerignore
COPY . .

# Build
RUN rustup target add arm-unknown-linux-gnueabi
RUN cargo build --features ${DB} --release --target=arm-unknown-linux-gnueabi -v

######################## RUNTIME IMAGE  ########################
# Create a new stage with a minimal image
# because we already have a binary built
FROM balenalib/rpi-debian:stretch

ENV ROCKET_ENV "staging"
ENV ROCKET_PORT=80
ENV ROCKET_WORKERS=10

RUN [ "cross-build-start" ]

# Install needed libraries
RUN apt-get update && apt-get install -y\
    openssl\
    ca-certificates\
    libmariadbclient-dev\
    --no-install-recommends\
 && rm -rf /var/lib/apt/lists/*

RUN mkdir /data

RUN [ "cross-build-end" ]  

VOLUME /data
EXPOSE 80

# Copies the files from the context (Rocket.toml file and web-vault)
# and the binary from the "build" stage to the current stage
COPY Rocket.toml .
COPY --from=vault /web-vault ./web-vault
COPY --from=build /app/target/arm-unknown-linux-gnueabi/release/bitwarden_rs .

# Configures the startup!
CMD ./bitwarden_rs