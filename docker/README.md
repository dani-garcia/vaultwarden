# Vaultwarden Container Building

To build and release new testing and stable releases of Vaultwarden we use `docker buildx bake`.<br>
This can be used locally by running the command your self, but it is also used by GitHub Actions.

This makes it easier for us to test and maintain the different architectures we provide.<br>
We also just have two Dockerfile's one for Debian and one for Alpine based images.<br>
With just these two files we can build both Debian and Alpine images for the following platforms:
 - amd64 (linux/amd64)
 - arm64 (linux/arm64)
 - armv7 (linux/arm/v7)
 - armv6 (linux/arm/v6)

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
# To unistall
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

Start the the initialization, this only needs to be done once.

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

## Variables supported
| Variable              | default | description |
| --------------------- | ------------------ | ----------- |
| CARGO_PROFILE         | null               | Which cargo profile to use. `null` means what is defined in the Dockerfile                         |
| DB                    | null               | Which `features` to build. `null` means what is defined in the Dockerfile                          |
| SOURCE_REPOSITORY_URL | null               | The source repository form where this build is triggered                                           |
| SOURCE_COMMIT         | null               | The commit hash of the current commit for this build                                               |
| SOURCE_VERSION        | null               | The current exact tag of this commit, else the last tag and the first 8 chars of the source commit |
| BASE_TAGS             | testing            | Tags to be used. Can be a comma separated value like "latest,1.29.2"                               |
| CONTAINER_REGISTRIES  | vaultwarden/server | Comma separated value of container registries. Like `ghcr.io/dani-garcia/vaultwarden,docker.io/vaultwarden/server` |
