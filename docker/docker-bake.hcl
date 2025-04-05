// ==== Baking Variables ====

// Set which cargo profile to use, dev or release for example
// Use the value provided in the Dockerfile as default
variable "CARGO_PROFILE" {
  default = null
}

// Set which DB's (features) to enable
// Use the value provided in the Dockerfile as default
variable "DB" {
  default = null
}

// The repository this build was triggered from
variable "SOURCE_REPOSITORY_URL" {
  default = null
}

// The commit hash of the current commit this build was triggered on
variable "SOURCE_COMMIT" {
  default = null
}

// The version of this build
// Typically the current exact tag of this commit,
// else the last tag and the first 8 characters of the source commit
variable "SOURCE_VERSION" {
  default = null
}

// This can be used to overwrite SOURCE_VERSION
// It will be used during the build.rs building stage
variable "VW_VERSION" {
  default = null
}

// The base tag(s) to use
// This can be a comma separated value like "testing,1.29.2"
variable "BASE_TAGS" {
  default = "testing"
}

// Which container registries should be used for the tagging
// This can be a comma separated value
// Use a full URI like `ghcr.io/dani-garcia/vaultwarden,docker.io/vaultwarden/server`
variable "CONTAINER_REGISTRIES" {
  default = "vaultwarden/server"
}


// ==== Baking Groups ====

group "default" {
  targets = ["debian"]
}


// ==== Shared Baking ====
function "labels" {
  params = []
  result = {
    "org.opencontainers.image.description" = "Unofficial Bitwarden compatible server written in Rust - ${SOURCE_VERSION}"
    "org.opencontainers.image.licenses" = "AGPL-3.0-only"
    "org.opencontainers.image.documentation" = "https://github.com/dani-garcia/vaultwarden/wiki"
    "org.opencontainers.image.url" = "https://github.com/dani-garcia/vaultwarden"
    "org.opencontainers.image.created" =  "${formatdate("YYYY-MM-DD'T'hh:mm:ssZZZZZ", timestamp())}"
    "org.opencontainers.image.source" = "${SOURCE_REPOSITORY_URL}"
    "org.opencontainers.image.revision" = "${SOURCE_COMMIT}"
    "org.opencontainers.image.version" = "${SOURCE_VERSION}"
  }
}

target "_default_attributes" {
  labels = labels()
  args = {
    DB = "${DB}"
    CARGO_PROFILE = "${CARGO_PROFILE}"
    VW_VERSION = "${VW_VERSION}"
  }
}


// ==== Debian Baking ====

// Default Debian target, will build a container using the hosts platform architecture
target "debian" {
  inherits = ["_default_attributes"]
  dockerfile = "docker/Dockerfile.debian"
  tags = generate_tags("", platform_tag())
  output = ["type=docker"]
}

// Multi Platform target, will build one tagged manifest with all supported architectures
// This is mainly used by GitHub Actions to build and push new containers
target "debian-multi" {
  inherits = ["debian"]
  platforms = ["linux/amd64", "linux/arm64", "linux/arm/v7", "linux/arm/v6"]
  tags = generate_tags("", "")
  output = [join(",", flatten([["type=registry"], image_index_annotations()]))]
}

// Per platform targets, to individually test building per platform locally
target "debian-amd64" {
  inherits = ["debian"]
  platforms = ["linux/amd64"]
  tags = generate_tags("", "-amd64")
}

target "debian-arm64" {
  inherits = ["debian"]
  platforms = ["linux/arm64"]
  tags = generate_tags("", "-arm64")
}

target "debian-armv7" {
  inherits = ["debian"]
  platforms = ["linux/arm/v7"]
  tags = generate_tags("", "-armv7")
}

target "debian-armv6" {
  inherits = ["debian"]
  platforms = ["linux/arm/v6"]
  tags = generate_tags("", "-armv6")
}

// ==== Start of unsupported Debian architecture targets ===
// These are provided just to help users build for these rare platforms
// They will not be built by default
target "debian-386" {
  inherits = ["debian"]
  platforms = ["linux/386"]
  tags = generate_tags("", "-386")
  args = {
    TARGET_PKG_CONFIG_PATH = "/usr/lib/i386-linux-gnu/pkgconfig"
  }
}

target "debian-ppc64le" {
  inherits = ["debian"]
  platforms = ["linux/ppc64le"]
  tags = generate_tags("", "-ppc64le")
}

target "debian-s390x" {
  inherits = ["debian"]
  platforms = ["linux/s390x"]
  tags = generate_tags("", "-s390x")
}
// ==== End of unsupported Debian architecture targets ===

// A Group to build all platforms individually for local testing
group "debian-all" {
  targets = ["debian-amd64", "debian-arm64", "debian-armv7", "debian-armv6"]
}


// ==== Alpine Baking ====

// Default Alpine target, will build a container using the hosts platform architecture
target "alpine" {
  inherits = ["_default_attributes"]
  dockerfile = "docker/Dockerfile.alpine"
  tags = generate_tags("-alpine", platform_tag())
  output = ["type=docker"]
}

// Multi Platform target, will build one tagged manifest with all supported architectures
// This is mainly used by GitHub Actions to build and push new containers
target "alpine-multi" {
  inherits = ["alpine"]
  platforms = ["linux/amd64", "linux/arm64", "linux/arm/v7", "linux/arm/v6"]
  tags = generate_tags("-alpine", "")
  output = [join(",", flatten([["type=registry"], image_index_annotations()]))]
}

// Per platform targets, to individually test building per platform locally
target "alpine-amd64" {
  inherits = ["alpine"]
  platforms = ["linux/amd64"]
  tags = generate_tags("-alpine", "-amd64")
}

target "alpine-arm64" {
  inherits = ["alpine"]
  platforms = ["linux/arm64"]
  tags = generate_tags("-alpine", "-arm64")
}

target "alpine-armv7" {
  inherits = ["alpine"]
  platforms = ["linux/arm/v7"]
  tags = generate_tags("-alpine", "-armv7")
}

target "alpine-armv6" {
  inherits = ["alpine"]
  platforms = ["linux/arm/v6"]
  tags = generate_tags("-alpine", "-armv6")
}

// A Group to build all platforms individually for local testing
group "alpine-all" {
  targets = ["alpine-amd64", "alpine-arm64", "alpine-armv7", "alpine-armv6"]
}


// ==== Bake everything locally ====

group "all" {
  targets = ["debian-all", "alpine-all"]
}


// ==== Baking functions ====

// This will return the local platform as amd64, arm64 or armv7 for example
// It can be used for creating a local image tag
function "platform_tag" {
  params = []
  result = "-${replace(replace(BAKE_LOCAL_PLATFORM, "linux/", ""), "/", "")}"
}


function "get_container_registries" {
  params = []
  result = flatten(split(",", CONTAINER_REGISTRIES))
}

function "get_base_tags" {
  params = []
  result = flatten(split(",", BASE_TAGS))
}

function "generate_tags" {
  params = [
    suffix,   // What to append to the BASE_TAG when needed, like `-alpine` for example
    platform  // the platform we are building for if needed
  ]
  result = flatten([
    for registry in get_container_registries() :
      [for base_tag in get_base_tags() :
        concat(
          # If the base_tag contains latest, and the suffix contains `-alpine` add a `:alpine` tag too
          base_tag == "latest" ? suffix == "-alpine" ? ["${registry}:alpine${platform}"] : [] : [],
          # The default tagging strategy
          ["${registry}:${base_tag}${suffix}${platform}"]
        )
      ]
  ])
}

function "image_index_annotations" {
  params = []
  result = flatten([
    for key, value in labels() :
      value != null ? formatlist("annotation-index.%s=%s", "${key}", "${value}") : []
  ])
}
