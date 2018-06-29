
# Bitwarden_RS
This project is an unofficial implementation of the [Bitwarden Core Server](https://github.com/bitwarden/core) written in [Rust](https://www.rust-lang.org/).

*(Note: This project is not associated with the [Bitwarden](https://bitwarden.com/) project nor 8bit Solutions LLC.)*

# Build/Run
This project can be built and deployed in two ways:

## Docker Setup (Easy)
Install [Docker](https://www.docker.com/) to your system and then, from the project root, run:
```sh
# Build the docker image:
docker build -t bitwarden_rs .

# Run the docker image with a docker volume:
docker run --name bitwarden_rs -t --rm -v bw_data:/data -p 80:80 bitwarden_rs
```
Then visit [http://localhost:80](http://localhost:80)

## Manual Setup (Advanced)
### Dependencies
- `Rust nightly` (strongly recommended to use [rustup](https://rustup.rs/))
- `OpenSSL` (should be available in path, install through your system's package manager or use the [prebuilt binaries](https://wiki.openssl.org/index.php/Binaries))
- `NodeJS` (required to build the web-vault, (install through your system's package manager or use the [prebuilt binaries](https://nodejs.org/en/download/))

### Install the web-vault
Download the latest official release from the [releases page](https://github.com/bitwarden/web/releases) and extract it.

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

Then, run the following from the `web-vault` directory:
```sh
npm install
npx gulp dist:selfHosted
```

Finally copy the contents of the `web-vault/dist` folder into the `bitwarden_rs/web-vault` folder.

### Running
```sh
cargo run
```
Then visit [http://localhost:80](http://localhost:80)

## How to recreate database schemas (for developers)
Install diesel-cli with cargo:
```sh
cargo install diesel_cli --no-default-features --features sqlite-bundled
```

Make sure that the correct path to the database is in the `.env` file.

If you want to modify the schemas, create a new migration with:
```
diesel migration generate <name>
```

Modify the *.sql files, making sure that any changes are reverted in the down.sql file.

Apply the migrations and save the generated schemas as follows:
```sh
diesel migration redo

# This step should be done automatically when using diesel-cli > 1.3.0
# diesel print-schema > src/db/schema.rs
```
