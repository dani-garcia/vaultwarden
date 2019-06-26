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
# Musl build image for statically compiled binary
FROM clux/muslrust:nightly-2018-12-01 as build

# set sqlite as default for DB ARG for backward comaptibility
ARG DB=sqlite

ENV USER "root"

# Install needed libraries
RUN apt-get update && apt-get install -y\
    libmysqlclient-dev\
    --no-install-recommends\
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copies the complete project
# To avoid copying unneeded files, use .dockerignore
COPY . .

RUN rustup target add x86_64-unknown-linux-musl

# Make sure that we actually build the project
RUN touch src/main.rs

# Build
RUN cargo build --features ${DB} --release

######################## RUNTIME IMAGE  ########################
# Create a new stage with a minimal image
# because we already have a binary built
FROM alpine:3.9

ENV ROCKET_ENV "staging"
ENV ROCKET_PORT=80
ENV ROCKET_WORKERS=10
ENV SSL_CERT_DIR=/etc/ssl/certs

# Install needed libraries
RUN apk add \
        openssl \
        mariadb-connector-c \
        ca-certificates \
    && rm /var/cache/apk/*

RUN mkdir /data
VOLUME /data
EXPOSE 80
EXPOSE 3012

# Copies the files from the context (Rocket.toml file and web-vault)
# and the binary from the "build" stage to the current stage
COPY Rocket.toml .
COPY --from=vault /web-vault ./web-vault
COPY --from=build /app/target/x86_64-unknown-linux-musl/release/bitwarden_rs .

# Configures the startup!
CMD ./bitwarden_rs
