## Easy setup (Docker)
Install Docker to your system and then, from the project root, run:
```sh
# Build the docker image:
docker build -t dani/bitwarden_rs .

# Run the docker image with a docker volume:
docker volume create bw_data
docker run --name bitwarden_rs -t --init --rm --mount source=bw_data,target=/data -p 8000:80 dani/bitwarden_rs
```

#### Other possible Docker options

To run the container in the background, add the `-d` parameter.

To check the logs when in background, run `docker logs bitwarden_rs`

To stop the container in background, run `docker stop bitwarden_rs`

To make sure the container is restarted automatically, add the `--restart unless-stopped` parameter

To run the image with a host bind, change the `--mount` parameter to:
```
--mount type=bind,source=<absolute_path>,target=/data
```
Where <absolute_path> is an absolute path in the hosts file system (e.g. C:\bitwarden\data)


## How to compile bitwarden_rs
Install `rust nightly`, in Windows the recommended way is through `rustup`.

Install the `openssl` library, in Windows the best option is Microsoft's `vcpkg`,
on other systems use their respective package managers.

Then run:
```sh
cargo run
# or
cargo build
```

## How to install the web-vault locally
If you're using docker image, you can just update `VAULT_VERSION` variable in Dockerfile and rebuild the image.

Install `node.js` and either `yarn` or `npm` (usually included with node)

Clone the web-vault outside the project:
```
git clone https://github.com/bitwarden/web.git web-vault
```

Modify `web-vault/settings.Production.json` to look like this:
```json
{
  "appSettings": {
    "apiUri": "/api",
    "identityUri": "/identity",
    "iconsUri": "/icons",
    "stripeKey": "",
    "braintreeKey": ""
  }
}
```

Then, run the following from the `web-vault` dir:
```sh
# With yarn (recommended)
yarn
yarn gulp dist:selfHosted

# With npm
npm install
npx gulp dist:selfHosted
```

Finally copy the contents of the `web-vault/dist` folder into the `bitwarden_rs/web-vault` folder.

## How to recreate database schemas
Install diesel-cli with cargo:
```sh
cargo install diesel_cli --no-default-features --features sqlite-bundled # Or use only sqlite to use the system version
```

Make sure that the correct path to the database is in the `.env` file.

If you want to modify the schemas, create a new migration with:
```
diesel migration generate <name>
```

Modify the *.sql files, making sure that any changes are reverted in the down.sql file.

Apply the migrations and save the generated schemas as follows:
```
diesel migration redo
diesel print-schema > src/db/schema.rs
```
