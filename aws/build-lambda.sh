#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

image="${VAULTWARDEN_LAMBDA_BUILD_IMAGE:-public.ecr.aws/codebuild/amazonlinux2-aarch64-standard:3.0}"
platform="${VAULTWARDEN_LAMBDA_BUILD_PLATFORM:-linux/arm64}"
package_path="${repo_root}/aws/vaultwarden-lambda.zip"

docker_tty_args=()
if [ -t 1 ]; then
    docker_tty_args=(-t)
fi

printf 'Building Lambda package with %s for %s\n' "${image}" "${platform}"

docker run \
    --rm \
    --pull=missing \
    --platform "${platform}" \
    "${docker_tty_args[@]}" \
    --entrypoint /bin/bash \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    -v "${repo_root}:/work" \
    -v vaultwarden-lambda-cargo-home:/root/.cargo \
    -v vaultwarden-lambda-rustup-home:/root/.rustup \
    -w /work \
    "${image}" \
    -lc '
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

restore_ownership() {
    for path in target aws/vaultwarden-lambda.zip; do
        if [ -e "$path" ]; then
            chown -R "${HOST_UID}:${HOST_GID}" "$path"
        fi
    done
}
trap restore_ownership EXIT

yum install -y krb5-devel openldap-devel unzip xz zip

if ! command -v rustup >/dev/null 2>&1; then
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable
fi

rustup default stable

if ! command -v cargo-lambda >/dev/null 2>&1; then
    curl -fsSL https://cargo-lambda.info/install.sh | sh
fi

cargo lambda build --verbose

cp /lib64/{libcrypt.so.2,liblber-2.4.so.2,libldap_r-2.4.so.2,libpq.so.5,libsasl2.so.3} \
    target/lambda/vaultwarden/

mkdir -p target/lambda/vaultwarden/web-vault
printf "%s\n" "<html><body><h1>Web Vault Placeholder</h1></body></html>" \
    > target/lambda/vaultwarden/web-vault/index.html

rm -f aws/vaultwarden-lambda.zip
(
    cd target/lambda/vaultwarden
    zip -r /work/aws/vaultwarden-lambda.zip .
)
'

printf 'Created %s\n' "${package_path}"
