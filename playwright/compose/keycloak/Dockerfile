FROM docker.io/library/debian:bookworm-slim as build

ENV DEBIAN_FRONTEND=noninteractive
ARG KEYCLOAK_VERSION

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y ca-certificates curl wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /

RUN wget -c https://github.com/keycloak/keycloak/releases/download/${KEYCLOAK_VERSION}/keycloak-${KEYCLOAK_VERSION}.tar.gz -O - | tar -xz

FROM docker.io/library/debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ARG KEYCLOAK_VERSION

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y ca-certificates curl wget \
    && rm -rf /var/lib/apt/lists/*

ARG JAVA_URL
ARG JAVA_VERSION

ENV JAVA_VERSION=${JAVA_VERSION}

RUN mkdir -p /opt/openjdk && cd /opt/openjdk \
    && wget -c "${JAVA_URL}"  -O - | tar -xz

WORKDIR /

COPY setup.sh /setup.sh
COPY --from=build /keycloak-${KEYCLOAK_VERSION}/bin /opt/keycloak/bin

CMD "/setup.sh"
