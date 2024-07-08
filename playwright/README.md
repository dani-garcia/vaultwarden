# Integration tests

This allows running integration tests using [Playwright](https://playwright.dev/).
\
It usse its own [test.env](/test/scenarios/test.env) with different ports to not collide with a running dev instance.

## Install

This rely on `docker` and the `compose` [plugin](https://docs.docker.com/compose/install/).
Databases (`Mariadb`, `Mysql` and `Postgres`) and `Playwright` will run in containers.

### Running Playwright outside docker

It's possible to run `Playwright` outside of the container, this remove the need to rebuild the image for each change.
You'll additionally need `nodejs` then run:

```bash
npm install
npx playwright install-deps
npx playwright install firefox
```

## Usage

To run all the tests:

```bash
DOCKER_BUILDKIT=1 docker compose --env-file test.env run Playwright
```

To force a rebuild of the Playwright image:
```bash
DOCKER_BUILDKIT=1 docker compose --env-file test.env build Playwright
```

To access the ui to easily run test individually and debug if needed (will not work in docker):

```bash
npx playwright test --ui
```

### DB

Projects are configured to allow to run tests only on specific database.
\
You can use:

```bash
DOCKER_BUILDKIT=1 docker compose --env-file test.env run Playwright test --project=mariadb
DOCKER_BUILDKIT=1 docker compose --env-file test.env run Playwright test --project=mysql
DOCKER_BUILDKIT=1 docker compose --env-file test.env run Playwright test --project=postgres
DOCKER_BUILDKIT=1 docker compose --env-file test.env run Playwright test --project=sqlite
```

### Running specific tests

To run a whole file you can :

```bash
DOCKER_BUILDKIT=1 docker compose --env-file test.env run Playwright test --project=sqlite tests/login.spec.ts
DOCKER_BUILDKIT=1 docker compose --env-file test.env run Playwright test --project=sqlite login
```

To run only a specifc test (It might fail if it has dependency):

```bash
DOCKER_BUILDKIT=1 docker compose --env-file test.env run Playwright test --project=sqlite -g "Account creation"
DOCKER_BUILDKIT=1 docker compose --env-file test.env run Playwright test --project=sqlite tests/login.spec.ts:16
```

## Writing scenario

When creating new scenario use the recorder to more easily identify elements (in general try to rely on visible hint to identify elements and not hidden ids).
This does not start the server, you will need to start it manually.

```bash
npx playwright codegen "http://127.0.0.1:8000"
```

## Override web-vault

It's possible to change the `web-vault` used by referencing a different `bw_web_builds` commit.

```bash
export PW_WV_REPO_URL=https://github.com/Timshel/oidc_web_builds.git
export PW_WV_COMMIT_HASH=8707dc76df3f0cceef2be5bfae37bb29bd17fae6
DOCKER_BUILDKIT=1 docker compose --env-file test.env build Playwright
```
