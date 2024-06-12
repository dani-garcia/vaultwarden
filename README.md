### Alternative implementation of the Bitwarden server API written in Rust and compatible with [upstream Bitwarden clients](https://bitwarden.com/download/)*, perfect for self-hosted deployment where running the official resource-heavy service might not be ideal.

📢 Note: This project was known as Bitwarden_RS and has been renamed to separate itself from the official Bitwarden server in the hopes of avoiding confusion and trademark/branding issues. Please see [#1642](https://github.com/dani-garcia/vaultwarden/discussions/1642) for more explanation.

---
[![Build](https://github.com/dani-garcia/vaultwarden/actions/workflows/build.yml/badge.svg)](https://github.com/dani-garcia/vaultwarden/actions/workflows/build.yml)
[![ghcr.io](https://img.shields.io/badge/ghcr.io-download-blue)](https://github.com/dani-garcia/vaultwarden/pkgs/container/vaultwarden)
[![Docker Pulls](https://img.shields.io/docker/pulls/vaultwarden/server.svg)](https://hub.docker.com/r/vaultwarden/server)
[![Quay.io](https://img.shields.io/badge/Quay.io-download-blue)](https://quay.io/repository/vaultwarden/server)
[![Dependency Status](https://deps.rs/repo/github/dani-garcia/vaultwarden/status.svg)](https://deps.rs/repo/github/dani-garcia/vaultwarden)
[![GitHub Release](https://img.shields.io/github/release/dani-garcia/vaultwarden.svg)](https://github.com/dani-garcia/vaultwarden/releases/latest)
[![AGPL-3.0 Licensed](https://img.shields.io/github/license/dani-garcia/vaultwarden.svg)](https://github.com/dani-garcia/vaultwarden/blob/main/LICENSE.txt)
[![Matrix Chat](https://img.shields.io/matrix/vaultwarden:matrix.org.svg?logo=matrix)](https://matrix.to/#/#vaultwarden:matrix.org)

Image is based on [Rust implementation of Bitwarden API](https://github.com/dani-garcia/vaultwarden).

**This project is not associated with the [Bitwarden](https://bitwarden.com/) project nor Bitwarden, Inc.**

#### ⚠️**IMPORTANT**⚠️: When using this server, please report any bugs or suggestions to us directly (look at the bottom of this page for ways to get in touch), regardless of whatever clients you are using (mobile, desktop, browser...). DO NOT use the official support channels.

---

## Features

Basically full implementation of Bitwarden API is provided including:

 * Organizations support
 * Attachments and Send
 * Vault API support
 * Serving the static files for Vault interface
 * Website icons API
 * Authenticator and U2F support
 * YubiKey and Duo support
 * Emergency Access

## Installation

## Docker compose
This example assumes that you have [installed](https://docs.docker.com/compose/install/) Docker Compose. This configuration can be used either for local servers that are not open to the 'outside world', or as a template for a [reverse proxy](https://github.com/dani-garcia/vaultwarden/wiki/Proxy-examples).

Start by creating a new directory at your preferred location and changing into it. Next, create the `compose.yml` (or `docker-compose.yml` for legacy versions)

```yaml
services:
  vaultwarden:
    image: vaultwarden/server:latest
    container_name: vaultwarden
    restart: always
    environment:
      # DOMAIN: "https://vaultwarden.example.com"  # required when using a reverse proxy; your domain; vaultwarden needs to know it's https to work properly with attachments
      SIGNUPS_ALLOWED: "true" # Deactivate this with "false" after you have created your account so that no strangers can register
    volumes:
      - ./vw-data:/data # the path before the : can be changed
    ports:
      - 80:80 # you can replace the port before the : with your preferred port
```

to create and run the container, run:
```bash
docker compose up -d && docker compose logs -f
```

to update and run the container, run:
```bash
docker compose pull && docker compose up -d && docker compose logs -f
```

## Docker run
Pull the docker image and mount a volume from the host for persistent storage:

```sh
docker pull vaultwarden/server:latest
docker run -d --name vaultwarden -v /vw-data/:/data/ --restart unless-stopped -p 80:80 vaultwarden/server:latest
```
This will preserve any persistent data under /vw-data/, you can adapt the path to whatever suits you.

**IMPORTANT**: Most modern web browsers disallow the use of Web Crypto APIs in insecure contexts. In this case, you might get an error like `Cannot read property 'importKey'`. To solve this problem, you need to access the web vault via HTTPS or localhost.

This can be configured in [vaultwarden directly](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-HTTPS) or using a third-party reverse proxy ([some examples](https://github.com/dani-garcia/vaultwarden/wiki/Proxy-examples)).

If you have an available domain name, you can get HTTPS certificates with [Let's Encrypt](https://letsencrypt.org/), or you can generate self-signed certificates with utilities like [mkcert](https://github.com/FiloSottile/mkcert). Some proxies automatically do this step, like Caddy (see examples linked above).

## Usage
See the [vaultwarden wiki](https://github.com/dani-garcia/vaultwarden/wiki) for more information on how to configure and run the vaultwarden server.

## Get in touch
To ask a question, offer suggestions or new features or to get help configuring or installing the software, please use [GitHub Discussions](https://github.com/dani-garcia/vaultwarden/discussions) or [the forum](https://vaultwarden.discourse.group/).

If you spot any bugs or crashes with vaultwarden itself, please [create an issue](https://github.com/dani-garcia/vaultwarden/issues/). Make sure you are on the latest version and there aren't any similar issues open, though!

If you prefer to chat, we're usually hanging around at [#vaultwarden:matrix.org](https://matrix.to/#/#vaultwarden:matrix.org) room on Matrix. Feel free to join us!

### Sponsors
Thanks for your contribution to the project!

<!--
<table>
  <tr>
    <td align="center">
      <a href="https://github.com/username">
        <img src="https://avatars.githubusercontent.com/u/725423?s=75&v=4" width="75px;" alt="username"/>
        <br />
        <sub><b>username</b></sub>
      </a>
  </td>
  </tr>
</table>

<br/>
-->

<table>
  <tr>
    <td align="center">
       <a href="https://github.com/themightychris" style="width: 75px">
        <sub><b>Chris Alfano</b></sub>
      </a>
    </td>
  </tr>
  <tr>
    <td align="center">
      <a href="https://github.com/numberly" style="width: 75px">
        <sub><b>Numberly</b></sub>
      </a>
    </td>
  </tr>
  <tr>
    <td align="center">
      <a href="https://github.com/IQ333777" style="width: 75px">
        <sub><b>IQ333777</b></sub>
      </a>
    </td>
  </tr>
</table>
