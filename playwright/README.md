# OpenID Keycloak scenarios

This allows running integration tests using [Playwright](https://playwright.dev/).
\
It usse its own [test.env](/test/scenarios/test.env) with different ports to not collide with a running dev instance.

## Install

```bash
npm install
npx playwright install firefox
```

## Usage

To run all the tests:

```bash
npx playwright test
```

To access the ui to easily run test individually and debug if needed:

```bash
npx playwright test --ui
```

### DB

Projects are configured to allow to run tests only on specific database.
\
You can use:

```bash
npx playwright test --project sqllite
npx playwright test --project postgres
npx playwright test --project mysql
```

### Running specific tests

To run a whole file you can :

```bash
npx playwright test --project=sqllite tests/login.spec.ts
npx playwright test --project=sqllite login
```

To run only a specifc test (It might fail if it has dependency):

```bash
npx playwright test --project=sqllite -g "Account creation"
npx playwright test --project=sqllite tests/login.spec.ts:16
```

## Writing scenario

When creating new scenario use the recorder to more easily identify elements (in general try to rely on visible hint to identify elements and not hidden ids).
This does not start the server, you will need to start it manually.

```bash
npx playwright codegen "http://127.0.0.1:8000"
```
