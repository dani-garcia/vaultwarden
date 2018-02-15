## Easy setup (Docker)
Install Docker to your system and then, from the project root, run:
```
# Build the docker image:
docker build -t dani/bitwarden_rs .

# Run the docker image with a docker volume:
docker volume create bw_data
docker run --name bitwarden_rs -it --init --rm --mount source=bw_data,target=/data -p 8000:80 dani/bitwarden_rs

# OR, Run the docker image with a host bind, where <absolute_path> is the absolute path to a folder in the host:
docker run --name bitwarden_rs -it --init --rm --mount type=bind,source=<absolute_path>,target=/data -p 8000:80 dani/bitwarden_rs
```

## How to compile bitwarden_rs
Install `rust nightly`, in Windows the recommended way is through `rustup`.

Install the `sqlite3`, and `openssl` libraries, in Windows the best option is Microsoft's `vcpkg`,
on other systems use their respective package managers.

Then run:
```
cargo run --bin bitwarden_rs
# or
cargo build
```

## How to update the web-vault used
Install `node.js` and either `yarn` or `npm` (usually included with node)
Clone the web-vault outside the project:
```
git clone https://github.com/bitwarden/web.git web-vault
```

Modify `web-vault/settings.json` to look like this:
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
```
# With yarn (recommended)
yarn
yarn gulp dist:selfHosted

# With npm
npm install
npx gulp dist:selfHosted
```

Finally copy the contents of the `web-vault/dist` folder into the `bitwarden_rs/web-vault` folder.

## How to create the RSA signing key for JWT
Generate the RSA key:
```
openssl genrsa -out data/private_rsa_key.pem
```

Convert the generated key to .DER:
```
openssl rsa -in data/private_rsa_key.pem -outform DER -out data/private_rsa_key.der
```

And generate the public key:
```
openssl rsa -in data/private_rsa_key.der -inform DER -RSAPublicKey_out -outform DER -out data/public_rsa_key.der
```

## How to recreate database schemas
Install diesel-cli with cargo:
```
cargo install diesel_cli --no-default-features --features sqlite
```

Make sure that the correct path to the database is in the `.env` file.

If you want to modify the schemas, create a new migration with:
```
diesel migration generate <name>
```

Modify the *.sql files, making sure that any changes are reverted
in the down.sql file.

Apply the migrations and save the generated schemas as follows:
```
diesel migration redo
diesel print-schema > src/db/schema.rs
```
