### This is a Bitwarden server API implementation written in Rust compatible with [upstream Bitwarden clients](https://bitwarden.com/#download)*, perfect for self-hosted deployment where running the official resource-heavy service might not be ideal.

---

[![Travis Build Status](https://travis-ci.org/dani-garcia/bitwarden_rs.svg?branch=master)](https://travis-ci.org/dani-garcia/bitwarden_rs)
[![Docker Pulls](https://img.shields.io/docker/pulls/mprasil/bitwarden.svg)](https://hub.docker.com/r/mprasil/bitwarden)
[![Dependency Status](https://deps.rs/repo/github/dani-garcia/bitwarden_rs/status.svg)](https://deps.rs/repo/github/dani-garcia/bitwarden_rs)
[![GitHub Release](https://img.shields.io/github/release/dani-garcia/bitwarden_rs.svg)](https://github.com/dani-garcia/bitwarden_rs/releases/latest)
[![GPL-3.0 Licensed](https://img.shields.io/github/license/dani-garcia/bitwarden_rs.svg)](https://github.com/dani-garcia/bitwarden_rs/blob/master/LICENSE.txt)
[![Matrix Chat](https://img.shields.io/matrix/bitwarden_rs:matrix.org.svg?logo=matrix)](https://matrix.to/#/#bitwarden_rs:matrix.org)

Image is based on [Rust implementation of Bitwarden API](https://github.com/dani-garcia/bitwarden_rs).

_*Note, that this project is not associated with the [Bitwarden](https://bitwarden.com/) project nor 8bit Solutions LLC._

---

## Features

Basically full implementation of Bitwarden API is provided including:

 * Basic single user functionality
 * Organizations support
 * Attachments
 * Vault API support
 * Serving the static files for Vault interface
 * Website icons API
 * Authenticator and U2F support
 * YubiKey OTP

## Installation
Pull the docker image and mount a volume from the host for persistent storage:

```sh
docker pull mprasil/bitwarden:latest
docker run -d --name bitwarden -v /bw-data/:/data/ -p 80:80 mprasil/bitwarden:latest
```
This will preserve any persistent data under /bw-data/, you can adapt the path to whatever suits you.

## Usage
See the [bitwarden_rs wiki](https://github.com/dani-garcia/bitwarden_rs/wiki) for more information on how to configure and run the bitwarden_rs server.

## Get in touch

To ask an question, [raising an issue](https://github.com/dani-garcia/bitwarden_rs/issues/new) is fine, also please report any bugs spotted here.

If you prefer to chat, we're usually hanging around at [#bitwarden_rs:matrix.org](https://matrix.to/#/#bitwarden_rs:matrix.org) room on Matrix. Feel free to join us!
