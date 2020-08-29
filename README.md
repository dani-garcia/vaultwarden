### This is a Bitwarden server API implementation written in Rust compatible with [upstream Bitwarden clients](https://bitwarden.com/#download)*, perfect for self-hosted deployment where running the official resource-heavy service might not be ideal.

---

[![Travis Build Status](https://travis-ci.org/dani-garcia/bitwarden_rs.svg?branch=master)](https://travis-ci.org/dani-garcia/bitwarden_rs)
[![Docker Pulls](https://img.shields.io/docker/pulls/bitwardenrs/server.svg)](https://hub.docker.com/r/bitwardenrs/server)
[![Dependency Status](https://deps.rs/repo/github/dani-garcia/bitwarden_rs/status.svg)](https://deps.rs/repo/github/dani-garcia/bitwarden_rs)
[![GitHub Release](https://img.shields.io/github/release/dani-garcia/bitwarden_rs.svg)](https://github.com/dani-garcia/bitwarden_rs/releases/latest)
[![GPL-3.0 Licensed](https://img.shields.io/github/license/dani-garcia/bitwarden_rs.svg)](https://github.com/dani-garcia/bitwarden_rs/blob/master/LICENSE.txt)
[![Matrix Chat](https://img.shields.io/matrix/bitwarden_rs:matrix.org.svg?logo=matrix)](https://matrix.to/#/#bitwarden_rs:matrix.org)

Image is based on [Rust implementation of Bitwarden API](https://github.com/dani-garcia/bitwarden_rs).

**This project is not associated with the [Bitwarden](https://bitwarden.com/) project nor 8bit Solutions LLC.**

#### ⚠️**IMPORTANT**⚠️: When using this server, please report any bugs or suggestions to us directly (look at the bottom of this page for ways to get in touch), regardless of whatever clients you are using (mobile, desktop, browser...). DO NOT use the official support channels.

---

## Features

Basically full implementation of Bitwarden API is provided including:

 * Organizations support
 * Attachments
 * Vault API support
 * Serving the static files for Vault interface
 * Website icons API
 * Authenticator and U2F support
 * YubiKey and Duo support

## Installation
Pull the docker image and mount a volume from the host for persistent storage:

```sh
docker pull bitwardenrs/server:latest
docker run -d --name bitwarden -v /bw-data/:/data/ -p 80:80 bitwardenrs/server:latest
```
This will preserve any persistent data under /bw-data/, you can adapt the path to whatever suits you.

**IMPORTANT**: Some web browsers, like Chrome, disallow the use of Web Crypto APIs in insecure contexts. In this case, you might get an error like `Cannot read property 'importKey'`. To solve this problem, you need to access the web vault from HTTPS. 

This can be configured in [bitwarden_rs directly](https://github.com/dani-garcia/bitwarden_rs/wiki/Enabling-HTTPS) or using a third-party reverse proxy ([some examples](https://github.com/dani-garcia/bitwarden_rs/wiki/Proxy-examples)).

If you have an available domain name, you can get HTTPS certificates with [Let's Encrypt](https://letsencrypt.org/), or you can generate self-signed certificates with utilities like [mkcert](https://github.com/FiloSottile/mkcert). Some proxies automatically do this step, like Caddy (see examples linked above).

## Usage
See the [bitwarden_rs wiki](https://github.com/dani-garcia/bitwarden_rs/wiki) for more information on how to configure and run the bitwarden_rs server.

## Get in touch
To ask a question, offer suggestions or new features or to get help configuring or installing the software, please [use the forum](https://bitwardenrs.discourse.group/).

If you spot any bugs or crashes with bitwarden_rs itself, please [create an issue](https://github.com/dani-garcia/bitwarden_rs/issues/). Make sure there aren't any similar issues open, though!

If you prefer to chat, we're usually hanging around at [#bitwarden_rs:matrix.org](https://matrix.to/#/#bitwarden_rs:matrix.org) room on Matrix. Feel free to join us!

### Sponsors
Thanks for your contribution to the project!

- [@ChonoN](https://github.com/ChonoN)
