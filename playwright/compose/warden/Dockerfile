FROM playwright_oidc_vaultwarden_prebuilt AS prebuilt

FROM node:22-trixie AS build

ARG REPO_URL
ARG COMMIT_HASH

ENV REPO_URL=$REPO_URL
ENV COMMIT_HASH=$COMMIT_HASH

COPY --from=prebuilt /web-vault /web-vault

COPY build.sh /build.sh
RUN /build.sh

######################## RUNTIME IMAGE  ########################
FROM docker.io/library/debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# Create data folder and Install needed libraries
RUN mkdir /data && \
    apt-get update && apt-get install -y \
        --no-install-recommends \
        ca-certificates \
        curl \
        libmariadb-dev \
        libpq5 \
        openssl && \
    rm -rf /var/lib/apt/lists/*

# Self-signed TLS cert for the test server. The bundled web vault refuses
# to submit registration/login over HTTP ("Insecure URL not allowed");
# Rocket needs a cert+key to serve HTTPS. Self-contained layer so cert
# tweaks don't bust the apt-install layer above.
RUN mkdir /certs && \
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /certs/key.pem \
        -out /certs/cert.pem \
        -days 3650 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# Copies the files from the context (Rocket.toml file and web-vault)
# and the binary from the "build" stage to the current stage
WORKDIR /

COPY --from=prebuilt /start.sh .
COPY --from=prebuilt /vaultwarden .
COPY --from=build /web-vault ./web-vault

ENTRYPOINT ["/start.sh"]
