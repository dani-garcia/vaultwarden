# Alternative Implementation of the Bitwarden Server API Written in Rust and Compatible with [Upstream Bitwarden Clients](https://bitwarden.com/download/)

[![Build](https://github.com/dani-garcia/vaultwarden/actions/workflows/build.yml/badge.svg)](https://github.com/dani-garcia/vaultwarden/actions/workflows/build.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/vaultwarden/server.svg)](https://hub.docker.com/r/vaultwarden/server)
[![Quay.io](https://img.shields.io/badge/Quay.io-download-blue)](https://quay.io/repository/vaultwarden/server)
[![Dependency Status](https://deps.rs/repo/github/dani-garcia/vaultwarden/status.svg)](https://deps.rs/repo/github/dani-garcia/vaultwarden)
[![AGPL-3.0 Licensed](https://img.shields.io/github/license/dani-garcia/vaultwarden.svg)](https://github.com/dani-garcia/vaultwarden/blob/main/LICENSE.txt)
[![Matrix Chat](https://img.shields.io/matrix/vaultwarden:matrix.org.svg?logo=matrix)](https://matrix.to/#/#vaultwarden:matrix.org)

Our image is based on the [Rust implementation of the Bitwarden API](https://github.com/dani-garcia/vaultwarden). It is perfect for self-hosted deployment where running the official resource-heavy service might not be ideal. This project is not associated with the [Bitwarden](https://bitwarden.com/) project nor Bitwarden, Inc.

> [!NOTE]
> 
> This project was known as Bitwarden_RS and has been renamed to separate itself from the official Bitwarden server in the hopes of avoiding confusion and trademark/branding issues. Please see [#1642](https://github.com/dani-garcia/vaultwarden/discussions/1642) for more explanation.

> [!IMPORTANT]
>
> When using this server, please report any bugs or suggestions to us directly (look at the bottom of this page for ways to get in touch), regardless of whatever clients you are using (mobile, desktop, browser...). DO NOT use the official support channels.

## Features

This project is a full implementation of the Bitwarden API, including:

* Organizations support
* Attachments and Send
* Vault API support
* Serving the static files for Vault interface
* Website icons API
* Authenticator and U2F support
* YubiKey and Duo support
* Emergency Access

## Installation

### Docker / Podman

Pull the container image and mount a volume from the host for persistent storage:

```bash
docker run --rm --name vaultwarden --volume /vw-data/:/data/ --publish localhost:8080:80 vaultwarden/server:latest
```

This command preserves any persistent data under `/vw-data/` on your host. You can adapt the path to whatever suits you.

> [!CAUTION]
>
> Most modern web browsers disallow the use of Web Crypto APIs in insecure contexts. In this case, you might get an error like `Cannot read property 'importKey'`. To solve this problem, you need to access the web vault via HTTPS or localhost. This can be configured in [vaultwarden directly](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-HTTPS) or using a third-party reverse proxy ([examples](https://github.com/dani-garcia/vaultwarden/wiki/Proxy-examples)).

### Kubernetes

There is a [Helm chart for Vaultwarden](https://github.com/guerzon/vaultwarden).

## Usage

See the [Vaultwarden GitHub wiki](https://github.com/dani-garcia/vaultwarden/wiki) for more information on how to configure and run the vaultwarden server.

## Get in Touch

To ask a question, offer suggestions or new features, or to get help configuring or installing the software, please use [GitHub Discussions](https://github.com/dani-garcia/vaultwarden/discussions) or [the forum](https://vaultwarden.discourse.group/).

If you spot any bugs or crashes with vaultwarden itself, please [create an issue](https://github.com/dani-garcia/vaultwarden/issues/). Make sure you are on the latest version and there aren't any similar issues open, though!

If you prefer to chat, we're usually hanging around at [#vaultwarden:matrix.org](https://matrix.to/#/#vaultwarden:matrix.org) room on Matrix. Feel free to join us!

## Sponsors

Thanks for your contribution to the project!

* [**Chris Alfano**](https://github.com/themightychris)
* [**Numberly**](https://github.com/numberly)
* [**IQ333777**](https://github.com/IQ333777)
