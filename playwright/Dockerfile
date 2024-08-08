FROM docker.io/library/debian:bookworm-slim

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
	&& apt-get install -y --no-install-recommends docker.io docker-compose git nodejs npm \
	&& apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libmariadb-dev-compat \
        libpq5 \
        openssl

RUN mkdir /playwright
WORKDIR /playwright

COPY package.json .
RUN npm install && npx playwright install-deps && npx playwright install firefox

COPY docker-compose.yml Dockerfile test.env ./
COPY compose ./compose

COPY *.ts test.env ./
COPY tests ./tests

ENTRYPOINT ["/usr/bin/npx", "playwright"]
CMD ["test"]
