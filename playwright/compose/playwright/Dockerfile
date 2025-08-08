FROM docker.io/library/debian:bookworm-slim

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y ca-certificates curl \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" | tee /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        containerd.io \
        docker-buildx-plugin \
        docker-ce \
        docker-ce-cli \
        docker-compose-plugin \
        git \
        libmariadb-dev-compat \
        libpq5 \
        nodejs \
        npm \
        openssl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /playwright
WORKDIR /playwright

COPY package.json .
RUN npm install && npx playwright install-deps && npx playwright install firefox

COPY docker-compose.yml test.env ./
COPY compose ./compose

COPY *.ts test.env ./
COPY tests ./tests

ENTRYPOINT ["/usr/bin/npx", "playwright"]
CMD ["test"]
