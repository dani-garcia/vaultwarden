# OpenID Connect test setup

This `docker-compose` template allow to run locally a `VaultWarden` and [`Keycloak`](https://www.keycloak.org/) instance to test OIDC.

## Usage

You'll need `docker` and `docker-compose` ([cf](https://docs.docker.com/engine/install/)).

First create a copy of `.env.template` as `.env` (This is done to prevent commiting your custom settings, Ex `SMTP_`).

Then start the stack (the `profile` is required to run the `VaultWarden`) :

```bash
> DOCKER_BUILDKIT=1 docker-compose --profile VaultWarden up
....
keycloakSetup_1  | Logging into http://127.0.0.1:8080 as user admin of realm master
keycloakSetup_1  | Created new realm with id 'test'
keycloakSetup_1  | 74af4933-e386-4e64-ba15-a7b61212c45e
oidc_keycloakSetup_1 exited with code 0
```

Wait until `oidc_keycloakSetup_1 exited with code 0` which indicate the correct setup of the Keycloak realm, client and user (It's normal for this container to stop once the configuration is done).

Then you can access :

 - `VaultWarden` on http://127.0.0.1:8000 with the default user `test@yopmail.com/test`.
 - `Keycloak` on http://127.0.0.1:8080/admin/master/console/ with the default user `admin/admin`

To proceed with an SSO login after you enter the email, on the screen prompting for `Master Password` the SSO button should be visible.

## Running only Keycloak

Since the `VaultWarden` service is defined with a `profile` you can just use the default `docker-compose` command :

```bash
> docker-compose up
```

When running with a local VaultWarden you'll need to make the SSO button visible using :

```bash
sed -i 's#a\[routerlink="/sso"\],##' /web-vault/app/main.*.css
```

Otherwise you'll need to reveal the SSO login button using the debug console (F12)

 ```js
 document.querySelector('a[routerlink="/sso"]').style.setProperty("display", "inline-block", "important");
 ```

## To force rebuilding the VaultWarden image

Use `DOCKER_BUILDKIT=1 docker-compose --profile VaultWarden up --build VaultWarden`.

If after building the `Keycloak` configuration is not run, just interrupt and run without `--build`

## Configuration

All configuration for `keycloak` / `VaultWarden` / `keycloak_setup.sh` can be found in [.env](.env.template).
The content of the file will be loaded as environment variables in all containers.

- `keycloak` [configuration](https://www.keycloak.org/server/all-config) include `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD` and any variable prefixed `KC_` ([more information](https://www.keycloak.org/server/configuration#_example_configuring_the_db_url_host_parameter)).
- All `VaultWarden` configuration can be set (EX: `SMTP_*`)

## Cleanup

Use `docker-compose --profile VaultWarden down`.
