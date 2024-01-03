FROM docker.io/library/debian:trixie-slim

ARG KEYCLOAK_VERSION

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y ca-certificates curl jq openjdk-21-jdk-headless wget

WORKDIR /

RUN wget -c https://github.com/keycloak/keycloak/releases/download/${KEYCLOAK_VERSION}/keycloak-${KEYCLOAK_VERSION}.tar.gz -O - | tar -xz \
    && mkdir -p /opt/keycloak \
    && mv /keycloak-${KEYCLOAK_VERSION}/bin /opt/keycloak/bin \
    && rm -rf /keycloak-${KEYCLOAK_VERSION}

COPY setup.sh /setup.sh

CMD "/setup.sh"
