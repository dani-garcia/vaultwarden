// ==== Baking Variables ====

// Set which cargo provile to use, dev or release for example
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

// The commit hash of of the current commit this build was triggered on
variable "SOURCE_COMMIT" {
  default = null
}

// The version of this build
// Typically the current exact tag of this commit,
// else the last tag and the first 8 characters of the source commit
variable "SOURCE_VERSION" {
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

target "_default_attributes" {
  labels = {
    "org.opencontainers.image.licenses" = "AGPL-3.0-only"
    "org.opencontainers.image.documentation" = "https://github.com/dani-garcia/vaultwarden/wiki"
    "org.opencontainers.image.url" = "https://github.com/dani-garcia/vaultwarden"
    "org.opencontainers.image.created" =  "${formatdate("YYYY-MM-DD'T'hh:mm:ssZZZZZ", timestamp())}"
    "org.opencontainers.image.source" = "${SOURCE_REPOSITORY_URL}"
    "org.opencontainers.image.revision" = "${SOURCE_COMMIT}"
    "org.opencontainers.image.version" = "${SOURCE_VERSION}"
  }
  args = {
    DB = "${DB}"
    CARGO_PROFILE = "${CARGO_PROFILE}"
  }
}


// ==== Debian Baking ====

target "debian" {
  inherits = ["_default_attributes"]
  dockerfile = "docker/Dockerfile.debian"
  output = ["type=docker"]
  tags = generate_tags("", platform_tag())
}

target "debian-all" {
  inherits = ["debian"]
  platforms = ["linux/amd64", "linux/arm64", "linux/arm/v7", "linux/arm/v6"]
  tags = generate_tags("", "")
  output = ["type=registry"]
}


// ==== Alpine Baking ====

target "alpine" {
  inherits = ["_default_attributes"]
  dockerfile = "docker/Dockerfile.alpine"
  output = ["type=docker"]
  tags = generate_tags("-alpine", platform_tag())
}

target "alpine-all" {
  inherits = ["alpine"]
  platforms = ["linux/amd64", "linux/arm64", "linux/arm/v7", "linux/arm/v6"]
  tags = generate_tags("-alpine", "")
  output = ["type=registry"]
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
        concat(["${registry}:${base_tag}${suffix}${platform}"])]
  ])
}
