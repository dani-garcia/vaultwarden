### This is a Bitwarden server API implementation written in Rust compatible with [upstream Bitwarden clients](https://bitwarden.com/#download)*, perfect for self-hosted deployment where running the official resource-heavy service might not be ideal.

---

[![Travis Build Status](https://travis-ci.org/dani-garcia/bitwarden_rs.svg?branch=master)](https://travis-ci.org/dani-garcia/bitwarden_rs)
[![Dependency Status](https://deps.rs/repo/github/dani-garcia/bitwarden_rs/status.svg)](https://deps.rs/repo/github/dani-garcia/bitwarden_rs)
[![GitHub Release](https://img.shields.io/github/release/dani-garcia/bitwarden_rs.svg)](https://github.com/dani-garcia/bitwarden_rs/releases/latest)
[![GPL-3.0 Licensed](https://img.shields.io/github/license/dani-garcia/bitwarden_rs.svg)](https://github.com/dani-garcia/bitwarden_rs/blob/master/LICENSE.txt)
[![Matrix Chat](https://matrix.to/img/matrix-badge.svg)](https://matrix.to/#/#bitwarden_rs:matrix.org)

Image is based on [Rust implementation of Bitwarden API](https://github.com/dani-garcia/bitwarden_rs).

_*Note, that this project is not associated with the [Bitwarden](https://bitwarden.com/) project nor 8bit Solutions LLC._

---

**Table of contents**

- [Features](#features)
- [Missing features](#missing-features)
- [Docker image usage](#docker-image-usage)
  - [Starting a container](#starting-a-container)
  - [Updating the bitwarden image](#updating-the-bitwarden-image)
- [Configuring bitwarden service](#configuring-bitwarden-service)
  - [Disable registration of new users](#disable-registration-of-new-users)
  - [Disable invitations](#disable-invitations)
  - [Enabling HTTPS](#enabling-https)
  - [Enabling WebSocket notifications](#enabling-websocket-notifications)
  - [Enabling U2F authentication](#enabling-u2f-authentication)
  - [Changing persistent data location](#changing-persistent-data-location)
    - [/data prefix:](#data-prefix)
    - [database name and location](#database-name-and-location)
    - [attachments location](#attachments-location)
    - [icons cache](#icons-cache)
  - [Changing the API request size limit](#changing-the-api-request-size-limit)
  - [Changing the number of workers](#changing-the-number-of-workers)
  - [SMTP configuration](#smtp-configuration)
  - [Password hint display](#password-hint-display)
  - [Disabling or overriding the Vault interface hosting](#disabling-or-overriding-the-vault-interface-hosting)
  - [Other configuration](#other-configuration)
- [Building your own image](#building-your-own-image)
- [Building binary](#building-binary)
- [Available packages](#available-packages)
  - [Arch Linux](#arch-linux)
- [Backing up your vault](#backing-up-your-vault)
  - [1. the sqlite3 database](#1-the-sqlite3-database)
  - [2. the attachments folder](#2-the-attachments-folder)
  - [3. the key files](#3-the-key-files)
  - [4. Icon Cache](#4-icon-cache)
- [Running the server with non-root user](#running-the-server-with-non-root-user)
- [Differences from upstream API implementation](#differences-from-upstream-api-implementation)
  - [Changing user email](#changing-user-email)
  - [Creating organization](#creating-organization)
  - [Inviting users into organization](#inviting-users-into-organization)
  - [Running on unencrypted connection](#running-on-unencrypted-connection)
- [Get in touch](#get-in-touch)

## Features

Basically full implementation of Bitwarden API is provided including:

 * Basic single user functionality
 * Organizations support
 * Attachments
 * Vault API support 
 * Serving the static files for Vault interface
 * Website icons API
 * Authenticator and U2F support
 
## Missing features
* Email confirmation
* Other two-factor systems:
  * YubiKey OTP (if your key supports U2F, you can use that)
  * Duo
  * Email codes

## Docker image usage

### Starting a container

The persistent data is stored under /data inside the container, so the only requirement for persistent deployment using Docker is to mount persistent volume at the path:

```
docker run -d --name bitwarden -v /bw-data/:/data/ -p 80:80 mprasil/bitwarden:latest
```

This will preserve any persistent data under `/bw-data/`, you can adapt the path to whatever suits you.

The service will be exposed on port 80.

### Updating the bitwarden image

Updating is straightforward, you just make sure to preserve the mounted volume. If you used the bind-mounted path as in the example above, you just need to `pull` the latest image, `stop` and `rm` the current container and then start a new one the same way as before:

```sh
# Pull the latest version
docker pull mprasil/bitwarden:latest

# Stop and remove the old container
docker stop bitwarden
docker rm bitwarden

# Start new container with the data mounted
docker run -d --name bitwarden -v /bw-data/:/data/ -p 80:80 mprasil/bitwarden:latest
```
Then visit [http://localhost:80](http://localhost:80)

In case you didn't bind mount the volume for persistent data, you need an intermediate step where you preserve the data with an intermediate container:

```sh
# Pull the latest version
docker pull mprasil/bitwarden:latest

# Create intermediate container to preserve data
docker run --volumes-from bitwarden --name bitwarden_data busybox true

# Stop and remove the old container
docker stop bitwarden
docker rm bitwarden

# Start new container with the data mounted
docker run -d --volumes-from bitwarden_data --name bitwarden -p 80:80 mprasil/bitwarden:latest

# Optionally remove the intermediate container
docker rm bitwarden_data

# Alternatively you can keep data container around for future updates in which case you can skip last step.
```

## Configuring bitwarden service

### Disable registration of new users

By default new users can register, if you want to disable that, set the `SIGNUPS_ALLOWED` env variable to `false`:

```sh
docker run -d --name bitwarden \
  -e SIGNUPS_ALLOWED=false \
  -v /bw-data/:/data/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```
Note: While users can't register on their own, they can still be invited by already registered users. Read bellow if you also want to disable that.

### Disable invitations

Even when registration is disabled, organization administrators or owners can invite users to join organization. This won't send email invitation to the users, but after they are invited, they can register with the invited email even if `SIGNUPS_ALLOWED` is actually set to `false`. You can disable this functionality completely by setting `INVITATIONS_ALLOWED` env variable to `false`:

```sh
docker run -d --name bitwarden \
  -e SIGNUPS_ALLOWED=false \
  -e INVITATIONS_ALLOWED=false \
  -v /bw-data/:/data/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```

### Enabling HTTPS
To enable HTTPS, you need to configure the `ROCKET_TLS`.

The values to the option must follow the format:
```
ROCKET_TLS={certs="/path/to/certs.pem",key="/path/to/key.pem"}
```
Where:
- certs: a path to a certificate chain in PEM format
- key: a path to a private key file in PEM format for the certificate in certs

```sh
docker run -d --name bitwarden \
  -e ROCKET_TLS='{certs="/ssl/certs.pem",key="/ssl/key.pem"}' \
  -v /ssl/keys/:/ssl/ \
  -v /bw-data/:/data/ \
  -p 443:80 \
  mprasil/bitwarden:latest
```
Note that you need to mount ssl files and you need to forward appropriate port.

Softwares used for getting certs are often using symlinks. If that is the case, both locations need to be accessible to the docker container.

Example: [certbot](https://certbot.eff.org/) will create a folder that contains the needed `cert.pem` and `privacy.pem` files in `/etc/letsencrypt/live/mydomain/`

These files are symlinked to `../../archive/mydomain/mykey.pem`

So to use from bitwarden container:

```sh
docker run -d --name bitwarden \
  -e ROCKET_TLS='{certs="/ssl/live/mydomain/cert.pem",key="/ssl/live/mydomain/privkey.pem"}' \
  -v /etc/letsencrypt/:/ssl/ \
  -v /bw-data/:/data/ \
  -p 443:80 \
  mprasil/bitwarden:latest
```
### Enabling WebSocket notifications
*Important: This does not apply to the mobile clients, which use push notifications.*

To enable WebSockets notifications, an external reverse proxy is necessary, and it must be configured to do the following:
- Route the `/notifications/hub` endpoint to the WebSocket server, by default at port `3012`, making sure to pass the `Connection` and `Upgrade` headers.
- Route everything else, including `/notifications/hub/negotiate`, to the standard Rocket server, by default at port `80`.
- If using Docker, you may need to map both ports with the `-p` flag

Example configurations are included in the [PROXY.md](https://github.com/dani-garcia/bitwarden_rs/blob/master/PROXY.md) file.

Note: The reason for this workaround is the lack of support for WebSockets from Rocket (though [it's a planned feature](https://github.com/SergioBenitez/Rocket/issues/90)), which forces us to launch a secondary server on a separate port.

### Enabling U2F authentication
To enable U2F authentication, you must be serving bitwarden_rs from an HTTPS domain with a valid certificate (Either using the included
HTTPS options or with a reverse proxy). We recommend using a free certificate from Let's Encrypt.

After that, you need to set the `DOMAIN` environment variable to the same address from where bitwarden_rs is being served:

```sh
docker run -d --name bitwarden \
  -e DOMAIN=https://bw.domain.tld \
  -v /bw-data/:/data/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```

Note that the value has to include the `https://` and it may include a port at the end (in the format of `https://bw.domain.tld:port`) when not using `443`.

### Changing persistent data location

#### /data prefix:

By default all persistent data is saved under `/data`, you can override this path by setting the `DATA_FOLDER` env variable:

```sh
docker run -d --name bitwarden \
  -e DATA_FOLDER=/persistent \
  -v /bw-data/:/persistent/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```

Notice, that you need to adapt your volume mount accordingly.

#### database name and location

Default is `$DATA_FOLDER/db.sqlite3`, you can change the path specifically for database using `DATABASE_URL` variable:

```sh
docker run -d --name bitwarden \
  -e DATABASE_URL=/database/bitwarden.sqlite3 \
  -v /bw-data/:/data/ \
  -v /bw-database/:/database/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```

Note, that you need to remember to mount the volume for both database and other persistent data if they are different.

#### attachments location

Default is `$DATA_FOLDER/attachments`, you can change the path using `ATTACHMENTS_FOLDER` variable:

```sh
docker run -d --name bitwarden \
  -e ATTACHMENTS_FOLDER=/attachments \
  -v /bw-data/:/data/ \
  -v /bw-attachments/:/attachments/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```

Note, that you need to remember to mount the volume for both attachments and other persistent data if they are different.

#### icons cache

Default is `$DATA_FOLDER/icon_cache`, you can change the path using `ICON_CACHE_FOLDER` variable:

```sh
docker run -d --name bitwarden \
  -e ICON_CACHE_FOLDER=/icon_cache \
  -v /bw-data/:/data/ \
  -v /icon_cache/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```

Note, that in the above example we don't mount the volume locally, which means it won't be persisted during the upgrade unless you use intermediate data container using `--volumes-from`. This will impact performance as bitwarden will have to re-download the icons on restart, but might save you from having stale icons in cache as they are not automatically cleaned.

### Changing the API request size limit

By default the API calls are limited to 10MB. This should be sufficient for most cases, however if you want to support large imports, this might be limiting you. On the other hand you might want to limit the request size to something smaller than that to prevent API abuse and possible DOS attack, especially if running with limited resources.

To set the limit, you can use the `ROCKET_LIMITS` variable. Example here shows 10MB limit for posted json in the body (this is the default):

```sh
docker run -d --name bitwarden \
  -e ROCKET_LIMITS={json=10485760} \
  -v /bw-data/:/data/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```

### Changing the number of workers

When you run bitwarden_rs, it spawns `2 * <number of cpu cores>` workers to handle requests. On some systems this might lead to low number of workers and hence slow performance, so the default in the docker image is changed to spawn 10 threads. You can override this setting to increase or decrease the number of workers by setting the `ROCKET_WORKERS` variable.

In the example bellow, we're starting with 20 workers:

```sh
docker run -d --name bitwarden \
  -e ROCKET_WORKERS=20 \
  -v /bw-data/:/data/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```

### SMTP configuration

You can configure bitwarden_rs to send emails via a SMTP agent:

```sh
docker run -d --name bitwarden \
  -e SMTP_HOST=<smtp.domain.tld> \
  -e SMTP_FROM=<bitwarden@domain.tld> \
  -e SMTP_PORT=587 \
  -e SMTP_SSL=true \
  -e SMTP_USERNAME=<username> \
  -e SMTP_PASSWORD=<password> \
  -v /bw-data/:/data/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```
  
When `SMTP_SSL` is set to `true`(this is the default), only TLSv1.1 and TLSv1.2 protocols will be accepted and `SMTP_PORT` will default to `587`. If set to `false`, `SMTP_PORT` will default to `25` and the connection won't be encrypted. This can be very insecure, use this setting only if you know what you're doing.

### Password hint display

Usually, password hints are sent by email. But as bitwarden_rs is made with small or personal deployment in mind, hints are also available from the password hint page, so you don't have to configure an email service. If you want to disable this feature, you can use the `SHOW_PASSWORD_HINT` variable:

```sh
docker run -d --name bitwarden \
  -e SHOW_PASSWORD_HINT=false \
  -v /bw-data/:/data/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```

### Disabling or overriding the Vault interface hosting

As a convenience bitwarden_rs image will also host static files for Vault web interface. You can disable this static file hosting completely by setting the WEB_VAULT_ENABLED variable.

```sh
docker run -d --name bitwarden \
  -e WEB_VAULT_ENABLED=false \
  -v /bw-data/:/data/ \
  -p 80:80 \
  mprasil/bitwarden:latest
```
Alternatively you can override the Vault files and provide your own static files to host. You can do that by mounting a path with your files over the `/web-vault` directory in the container. Just make sure the directory contains at least `index.html` file.

```sh
docker run -d --name bitwarden \
  -v /path/to/static/files_directory:/web-vault \
  -v /bw-data/:/data/ \
  -p 80:80 \
  mprasil/bitwarden:latest
``` 

Note that you can also change the path where bitwarden_rs looks for static files by providing the `WEB_VAULT_FOLDER` environment variable with the path.

### Other configuration

Though this is unlikely to be required in small deployment, you can fine-tune some other settings like number of workers using environment variables that are processed by [Rocket](https://rocket.rs), please see details in [documentation](https://rocket.rs/guide/configuration/#environment-variables).

## Building your own image

Clone the repository, then from the root of the repository run:

```sh
# Build the docker image:
docker build -t bitwarden_rs .
```

## Building binary

For building binary outside the Docker environment and running it locally without docker, please see [build instructions](https://github.com/dani-garcia/bitwarden_rs/blob/master/BUILD.md).

## Available packages

### Arch Linux

Bitwarden_rs is already packaged for Archlinux thanks to @mqus. There is an [AUR package](https://aur.archlinux.org/packages/bitwarden_rs) (optionally with the [vault web interface](https://aur.archlinux.org/packages/bitwarden_rs-vault/) ) available.

## Backing up your vault

### 1. the sqlite3 database

The sqlite3 database should be backed up using the proper sqlite3 backup command. This will ensure the database does not become corrupted if the backup happens during a database write.

```
sqlite3 /$DATA_FOLDER/db.sqlite3 ".backup '/$DATA_FOLDER/db-backup/backup.sq3'"
```

This command can be run via a CRON job everyday, however note that it will overwrite the same backup.sq3 file each time. This backup file should therefore be saved via incremental backup either using a CRON job command that appends a timestamp or from another backup app such as Duplicati.
 
### 2. the attachments folder

By default, this is located in `$DATA_FOLDER/attachments`

### 3. the key files

This is optional, these are only used to store tokens of users currently logged in, deleting them would simply log each user out forcing them to log in again. By default, these are located in the `$DATA_FOLDER` (by default /data in the docker). There are 3 files: rsa_key.der, rsa_key.pem, rsa_key.pub.der.

### 4. Icon Cache

This is optional, the icon cache can re-download itself however if you have a large cache, it may take a long time. By default it is located in `$DATA_FOLDER/icon_cache`

## Running the server with non-root user

The root user inside the container is already pretty limited in what it can do, so the default setup should be secure enough. However if you wish to go the extra mile to avoid using root even in container, here's how you can do that:

  1. Create a data folder that's owned by non-root user, so you can use that user to write persistent data. Get the user `id`. In linux you can run `stat <folder_name>` to get/verify the owner ID.
  2. When you run the container, you need to provide the user ID as one of the parameters. Note that this needs to be in the numeric form and not the user name, because docker would try to find such user defined inside the image, which would likely not be there or it would have different ID than your local user and hence wouldn't be able to write the persistent data. This can be done with the `--user` parameter.
  3. bitwarden_rs listens on port `80` inside the container by default, this [won't work with non-root user](https://www.w3.org/Daemon/User/Installation/PrivilegedPorts.html), because regular users aren't allowed to open port bellow `1024`. To overcome this, you need to configure server to listen on a different port, you can use `ROCKET_PORT` to do that.

Here's sample docker run, that uses user with id `1000` and with the port redirection configured, so that inside container the service is listening on port `8080` and docker translates that to external (host) port `80`:

```sh
docker run -d --name bitwarden \
  --user 1000 \
  -e ROCKET_PORT=8080 \
  -v /bw-data/:/data/ \
  -p 80:8080 \
  mprasil/bitwarden:latest
```

## Differences from upstream API implementation

### Changing user email

Because we don't have any SMTP functionality at the moment, there's no way to deliver the verification token when you try to change the email. User just needs to enter any random token to continue and the change will be applied.

### Creating organization

We use upstream Vault interface directly without any (significant) changes, this is why user is presented with paid options when creating organization. To create an organization, just use the free option, none of the limits apply when using bitwarden_rs as back-end API and after the organization is created it should behave like Enterprise organization.

### Inviting users into organization

The invited users won't get the invitation email, instead all already registered users will appear in the interface as if they already accepted the invitation. Organization admin then just needs to confirm them to be proper Organization members and to give them access to the shared secrets.

Invited users, that aren't registered yet will show up in the Organization admin interface as "Invited". At the same time an invitation record is created that allows the users to register even if [user registration is disabled](#disable-registration-of-new-users). (unless you [disable this functionality](#disable-invitations)) They will automatically become "Accepted" once they register. From there Organization admin can confirm them to give them access to Organization.

### Running on unencrypted connection

It is strongly recommended to run bitwarden_rs service over HTTPS. However the server itself while [supporting it](#enabling-https) does not strictly require such setup. This makes it a bit easier to spin up the service in cases where you can generally trust the connection (internal and secure network, access over VPN,..) or when you want to put the service behind HTTP proxy, that will do the encryption on the proxy end.

Running over HTTP is still reasonably secure provided you use really strong master password and that you avoid using web Vault over connection that is vulnerable to MITM attacks where attacker could inject javascript into your interface. However some forms of 2FA might not work in this setup and [Vault doesn't work in this configuration in Chrome](https://github.com/bitwarden/web/issues/254).

## Get in touch

To ask an question, [raising an issue](https://github.com/dani-garcia/bitwarden_rs/issues/new) is fine, also please report any bugs spotted here.

If you prefer to chat, we're usually hanging around at [#bitwarden_rs:matrix.org](https://matrix.to/#/#bitwarden_rs:matrix.org) room on Matrix. Feel free to join us!
