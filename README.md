This is Bitwarden server API implementation written in rust compatible with [upstream Bitwarden clients](https://bitwarden.com/#download)*, ideal for self-hosted deployment where running official resource-heavy service might not be ideal.

Image is based on [Rust implementation of Bitwarden API](https://github.com/dani-garcia/bitwarden_rs).

_*Note, that this project is not associated with the [Bitwarden](https://bitwarden.com/) project nor 8bit Solutions LLC._

## Features

Basically full implementation of Bitwarden API is provided including:

 * Basic single user functionality
 * Organizations support
 * Attachments
 * Vault API support 
 * Serving the static files for Vault interface
 * Website icons API

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

Note, that in the above example we don't mount the volume locally, which means it won't be persisted during the upgrade unless you use intermediate data container using `--volumes-from`. This will impact performance as bitwarden will have to re-dowload the icons on restart, but might save you from having stale icons in cache as they are not automatically cleaned.

### Other configuration

Though this is unlikely to be required in small deployment, you can fine-tune some other settings like number of workers using environment variables that are processed by [Rocket](https://rocket.rs), please see details in [documentation](https://rocket.rs/guide/configuration/#environment-variables).

## Building your own image

Clone the repository, then from the root of the repository run:

```sh
# Build the docker image:
docker build -t bitwarden_rs .
```

## Building binary

For building binary outside the Docker environment and running it locally without docker, please see [build instructions](BUILD.md).