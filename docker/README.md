# Vaultwarden Container Building

To build and release new testing and stable releases of Vaultwarden we use `docker buildx bake`.<br>
This can be used locally by running the command yourself, but it is also used by GitHub Actions.

This makes it easier for us to test and maintain the different architectures we provide.<br>
We also just have two Dockerfile's one for Debian and one for Alpine based images.<br>
With just these two files we can build both Debian and Alpine images for the following platforms:
 - amd64 (linux/amd64)
 - arm64 (linux/arm64)
 - armv7 (linux/arm/v7)
 - armv6 (linux/arm/v6)

Some unsupported platforms for Debian based images. These are not built and tested by default and are only provided to make it easier for users to build for these architectures.
- 386     (linux/386)
- ppc64le (linux/ppc64le)
- s390x   (linux/s390x)

To build these containers you need to enable QEMU binfmt support to be able to run/emulate architectures which are different then your host.<br>
This ensures the container build process can run binaries from other architectures.<br>

**NOTE**: Run all the examples below from the root of the repo.<br>


## How to install QEMU binfmt support

This is different per host OS, but most support this in some way.<br>

### Ubuntu/Debian
```bash
apt install binfmt-support qemu-user-static
```

### Arch Linux (others based upon it)
```bash
pacman -S qemu-user-static qemu-user-static-binfmt
```

### Fedora
```bash
dnf install qemu-user-static
```

### Others
There also is an option to use an other docker container to provide support for this.
```bash
# To install and activate
docker run --privileged --rm tonistiigi/binfmt --install arm64,arm
# To uninstall
docker run --privileged --rm tonistiigi/binfmt --uninstall 'qemu-*'
```


## Single architecture container building

You can build a container per supported architecture as long as you have QEMU binfmt support installed on your system.<br>

```bash
# Default bake triggers a Debian build using the hosts architecture
docker buildx bake --file docker/docker-bake.hcl

# Bake Debian ARM64 using a debug build
CARGO_PROFILE=dev \
SOURCE_COMMIT="$(git rev-parse HEAD)" \
docker buildx bake --file docker/docker-bake.hcl debian-arm64

# Bake Alpine ARMv6 as a release build
SOURCE_COMMIT="$(git rev-parse HEAD)" \
docker buildx bake --file docker/docker-bake.hcl alpine-armv6
```


## Local Multi Architecture container building

Start the initialization, this only needs to be done once.

```bash
# Create and use a new buildx builder instance which connects to the host network
docker buildx create --name vaultwarden --use --driver-opt network=host

# Validate it runs
docker buildx inspect --bootstrap

# Create a local container registry directly reachable on the localhost
docker run -d --name registry --network host registry:2
```

After that is done, you should be able to build and push to the local registry.<br>
Use the following command with the modified variables to bake the Alpine images.<br>
Replace `alpine` with `debian` if you want to build the debian multi arch images.

```bash
# Start a buildx bake using a debug build
CARGO_PROFILE=dev \
SOURCE_COMMIT="$(git rev-parse HEAD)" \
CONTAINER_REGISTRIES="localhost:5000/vaultwarden/server" \
docker buildx bake --file docker/docker-bake.hcl alpine-multi
```


## Using the `bake.sh` script

To make it a bit more easier to trigger a build, there also is a `bake.sh` script.<br>
This script calls `docker buildx bake` with all the right parameters and also generates the `SOURCE_COMMIT` and `SOURCE_VERSION` variables.<br>
This script can be called from both the repo root or within the docker directory.

So, if you want to build a Multi Arch Alpine container pushing to your localhost registry you can run this from within the docker directory. (Just make sure you executed the initialization steps above first)
```bash
CONTAINER_REGISTRIES="localhost:5000/vaultwarden/server" \
./bake.sh alpine-multi
```

Or if you want to just build a Debian container from the repo root, you can run this.
```bash
docker/bake.sh
```

You can append both `alpine` and `debian` with `-amd64`, `-arm64`, `-armv7` or `-armv6`, which will trigger a build for that specific platform.<br>
This will also append those values to the tag so you can see the builded container when running `docker images`.

You can also append extra arguments after the target if you want. This can be useful for example to print what bake will use.
```bash
docker/bake.sh alpine-all --print
```

### Testing baked images

To test these images you can run these images by using the correct tag and provide the platform.<br>
For example, after you have build an arm64 image via `./bake.sh debian-arm64` you can run:
```bash
docker run --rm -it \
  -e DISABLE_ADMIN_TOKEN=true \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -p8080:80 --platform=linux/arm64 \
  vaultwarden/server:testing-arm64
```


## Using the `podman-bake.sh` script

To also make building easier using podman, there is a `podman-bake.sh` script.<br>
This script calls `podman buildx build` with the needed parameters and the same as `bake.sh`, it will generate some variables automatically.<br>
This script can be called from both the repo root or within the docker directory.

**NOTE:** Unlike the `bake.sh` script, this only supports a single `CONTAINER_REGISTRIES`, and a single `BASE_TAGS` value, no comma separated values. It also only supports building separate architectures, no Multi Arch containers.

To build an Alpine arm64 image with only sqlite support and mimalloc, run this:
```bash
DB="sqlite,enable_mimalloc" \
./podman-bake.sh alpine-arm64
```

Or if you want to just build a Debian container from the repo root, you can run this.
```bash
docker/podman-bake.sh
```

You can append extra arguments after the target if you want. This can be useful for example to disable cache like this.
```bash
./podman-bake.sh alpine-arm64 --no-cache
```

For the podman builds you can, just like the `bake.sh` script, also append the architecture to build for that specific platform.<br>

### Testing podman builded images

The command to start a podman built container is almost the same as for the docker/bake built containers. The images start with `localhost/`, so you need to prepend that.

```bash
podman run --rm -it \
  -e DISABLE_ADMIN_TOKEN=true \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -p8080:80 --platform=linux/arm64 \
  localhost/vaultwarden/server:testing-arm64
```


## Variables supported
| Variable              | default | description |
| --------------------- | ------------------ | ----------- |
| CARGO_PROFILE         | null               | Which cargo profile to use. `null` means what is defined in the Dockerfile                                         |
| DB                    | null               | Which `features` to build. `null` means what is defined in the Dockerfile                                          |
| SOURCE_REPOSITORY_URL | null               | The source repository form where this build is triggered                                                           |
| SOURCE_COMMIT         | null               | The commit hash of the current commit for this build                                                               |
| SOURCE_VERSION        | null               | The current exact tag of this commit, else the last tag and the first 8 chars of the source commit                 |
| BASE_TAGS             | testing            | Tags to be used. Can be a comma separated value like "latest,1.29.2"                                               |
| CONTAINER_REGISTRIES  | vaultwarden/server | Comma separated value of container registries. Like `ghcr.io/dani-garcia/vaultwarden,docker.io/vaultwarden/server` |
| VW_VERSION            | null               | To override the `SOURCE_VERSION` value. This is also used by the `build.rs` code for example                       |
