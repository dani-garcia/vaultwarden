# Integration tests

This allows running integration tests using [Playwright](https://playwright.dev/).

It uses its own `test.env` with different ports to not collide with a running dev instance.

## Install

This relies on `docker` and the `compose` [plugin](https://docs.docker.com/compose/install/).
Databases (`Mariadb`, `Mysql` and `Postgres`) and `Playwright` will run in containers.

### Running Playwright outside docker

It is possible to run `Playwright` outside of the container, this removes the need to rebuild the image for each change.
You will additionally need `nodejs` then run:

```bash
npm install
npx playwright install-deps
npx playwright install firefox
```

## Usage

To run all the tests:

```bash
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env run Playwright
```

To force a rebuild of the Playwright image:
```bash
DOCKER_BUILDKIT=1 docker compose --env-file test.env build Playwright
```

To access the UI to easily run test individually and debug if needed (this will not work in docker):

```bash
npx playwright test --ui
```

### DB

Projects are configured to allow to run tests only on specific database.

You can use:

```bash
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env run Playwright test --project=mariadb
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env run Playwright test --project=mysql
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env run Playwright test --project=postgres
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env run Playwright test --project=sqlite
```

### SSO

To run the SSO tests:

```bash
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env run Playwright test --project sso-sqlite
```

### Keep services running

If you want you can keep the DB and Keycloak runnning (states are not impacted by the tests):

```bash
PW_KEEP_SERVICE_RUNNNING=true npx playwright test
```

### Running specific tests

To run a whole file you can :

```bash
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env run Playwright test --project=sqlite tests/login.spec.ts
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env run Playwright test --project=sqlite login
```

To run only a specifc test (It might fail if it has dependency):

```bash
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env run Playwright test --project=sqlite -g "Account creation"
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env run Playwright test --project=sqlite tests/login.spec.ts:16
```

## Writing scenario

When creating new scenario use the recorder to more easily identify elements
(in general try to rely on visible hint to identify elements and not hidden IDs).
This does not start the server, you will need to start it manually.

```bash
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env up Vaultwarden
npx playwright codegen "http://127.0.0.1:8003"
```

## Override web-vault

It is possible to change the `web-vault` used by referencing a different `bw_web_builds` commit.

Simplest is to set and uncomment `PW_WV_REPO_URL` and `PW_WV_COMMIT_HASH` in the `test.env`.
Ensure that the image is built with:

```bash
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env build Vaultwarden
```

You can check the result running:

```bash
DOCKER_BUILDKIT=1 docker compose --profile playwright --env-file test.env up Vaultwarden
```

# OpenID Connect test setup

Additionally this `docker-compose` template allows to run locally Vaultwarden,
[Keycloak](https://www.keycloak.org/) and [Maildev](https://github.com/timshel/maildev) to test OIDC.

## Setup

This rely on `docker` and the `compose` [plugin](https://docs.docker.com/compose/install/).
First create a copy of `.env.template` as `.env` (This is done to prevent committing your custom settings, Ex `SMTP_`).

## Usage

Then start the stack (the `profile` is required to run `Vaultwarden`) :

```bash
> docker compose --profile vaultwarden --env-file .env up
....
keycloakSetup_1  | Logging into http://127.0.0.1:8080 as user admin of realm master
keycloakSetup_1  | Created new realm with id 'test'
keycloakSetup_1  | 74af4933-e386-4e64-ba15-a7b61212c45e
oidc_keycloakSetup_1 exited with code 0
```

Wait until `oidc_keycloakSetup_1 exited with code 0` which indicates the correct setup of the Keycloak realm, client and user
(It is normal for this container to stop once the configuration is done).

Then you can access :

- `Vaultwarden` on http://0.0.0.0:8000 with the default user `test@yopmail.com/test`.
- `Keycloak` on http://0.0.0.0:8080/admin/master/console/ with the default user `admin/admin`
- `Maildev` on http://0.0.0.0:1080

To proceed with an SSO login after you enter the email, on the screen prompting for `Master Password` the SSO button should be visible.
To use your computer external ip (for example when testing with a phone) you will have to configure `KC_HTTP_HOST` and `DOMAIN`.

## Running only Keycloak

You can run just `Keycloak` with `--profile keycloak`:

```bash
> docker compose --profile keycloak --env-file .env up
```
When running with a local Vaultwarden, you can use a front-end build from [dani-garcia/bw_web_builds](https://github.com/dani-garcia/bw_web_builds/releases).

## Rebuilding the Vaultwarden

To force rebuilding the Vaultwarden image you can run

```bash
docker compose --profile vaultwarden --env-file .env build VaultwardenPrebuild Vaultwarden
```

## Configuration

All configuration for `keycloak` / `Vaultwarden` / `keycloak_setup.sh` can be found in [.env](.env.template).
The content of the file will be loaded as environment variables in all containers.

- `keycloak` [configuration](https://www.keycloak.org/server/all-config) includes `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD` and any variable prefixed `KC_` ([more information](https://www.keycloak.org/server/configuration#_example_configuring_the_db_url_host_parameter)).
- All `Vaultwarden` configuration can be set (EX: `SMTP_*`)

## Cleanup

Use `docker compose --profile vaultwarden down`.
