# Serverless release runbook

Use this runbook to upgrade this fork to a tagged Vaultwarden release and
deploy it to the existing AWS serverless stack. It is written for an agent or
operator starting from any branch in a possibly dirty worktree.

Loading this runbook does not authorize a deployment, history rewrite, or
other external mutation. Confirm that the user's request includes each action
before doing it.

## Deployment shape

The branch and runtime layers are ordered as follows:

```text
upstream release tag
  -> aws-ses (AWS HTTP integration and SES)
    -> main (Aurora DSQL and Lambda deployment)
```

Production uses:

- AWS profile `vaultwarden`.
- The stack name and region in `aws/samconfig.toml`.
- An ARM64 Lambda package built by `aws/build-lambda.sh`.
- A static web vault in the `WebVaultAssetsBucket` stack output.
- The web-vault version pinned by `docker/DockerSettings.yaml` at the release
  tag. Do not substitute the newest web-vault release.

Never infer account IDs, bucket names, function names, or CloudFront IDs from
old output. Resolve them from CloudFormation on every run.

## 1. Inventory and protect local state

From the repository root, record:

```sh
git status --short --branch
git remote -v
git branch -vv
git log --graph --decorate --oneline --all -30
```

The expected remotes are `upstream` for `dani-garcia/vaultwarden` and `origin`
for this fork. Stop if either URL is unexpected.

Preserve all existing changes before switching branches. Prefer a named stash
that includes untracked files, then record its object ID. Do not discard,
overwrite, or accidentally commit operator files such as
`aws/samconfig.toml` or database dumps.

```sh
git stash push --include-untracked --message "operator state before release"
git stash list --format='%gd %H %s' -1
```

If the tree was already clean, no stash is created. Do not assume an older
`stash@{0}` belongs to this run.

## 2. Authenticate the release

Set the requested release, fetch only from the upstream repository, and read
the immutable GitHub release notes:

```sh
release_version=1.37.2
git fetch upstream "refs/tags/${release_version}:refs/tags/${release_version}" \
  refs/heads/main:refs/remotes/upstream/main
gh release view "${release_version}" --repo dani-garcia/vaultwarden
git show --no-patch --format=fuller "${release_version}"
```

Confirm that the tag is annotated, identifies the expected release commit,
and is the immutable non-prerelease requested by the user. Run
`git tag -v "$release_version"` when GPG and the maintainer key are available.
If local signature verification is unavailable, explicitly record that fact;
do not describe the signature as locally verified.

Read the pinned web-vault version before changing branches:

```sh
git show "${release_version}:docker/DockerSettings.yaml"
```

## 3. Rebase the branch stack

Fetch `origin` immediately before rewriting and record its branch tips. These
object IDs become the force-with-lease expectations.

```sh
git fetch origin aws-ses main
old_aws_ses=$(git rev-parse aws-ses)
old_main=$(git rev-parse main)
origin_aws_ses=$(git rev-parse origin/aws-ses)
origin_main=$(git rev-parse origin/main)
```

Check that the local `aws-ses` tip is an ancestor of `main`. If it is stale,
identify the active SES commit on `main` before rebasing; preserve both tips
and align `aws-ses` to that commit. Never replay an obsolete HTTP client stack
whose changes have already landed upstream.

Create uniquely named local recovery branches. Never overwrite an existing
backup branch.

```sh
git branch "backup-aws-ses-pre-${release_version}" "${old_aws_ses}"
git branch "backup-main-pre-${release_version}" "${old_main}"
```

Rebase the AWS integration layer first:

```sh
git switch aws-ses
git rebase "${release_version}"
```

Resolve conflicts by preserving the upstream behavior and reapplying only the
OpenDAL transport, shared AWS HTTP client integration, and SES transport.
Review each complete resulting commit, not just conflict markers.

Replay only the commits that were above the old `aws-ses` tip onto its new tip:

```sh
git switch main
git rebase --onto aws-ses "${old_aws_ses}"
```

This form avoids replaying the old AWS integration commits as part of `main`.
Restore the operator stash only after both rebases finish and the worktree is
back on `main`. Resolve a stash conflict without losing either version.

Review these invariants before building:

```sh
git merge-base --is-ancestor "${release_version}" aws-ses
git merge-base --is-ancestor aws-ses main
git log --oneline "${release_version}..aws-ses"
git log --oneline "aws-ses..main"
git diff --check "${release_version}..main"
git status --short --branch
```

The release-to-`aws-ses` range should contain the upstreamable OpenDAL HTTP
transport, the separate AWS connector fix, and the SES layer unless the
release already includes any of them. The `aws-ses`-to-`main` range should
contain the DSQL, Lambda deployment, and release documentation commits.

## 4. Validate and publish source

Run formatting and an AWS-feature compile check before the packaging build:

```sh
cargo fmt --all -- --check
cargo check --locked --features aws
cargo test --locked --profile ci --features aws
cargo clippy --locked --profile ci --all-targets --features aws -- -D warnings
```

Review every new PostgreSQL migration against `migrations/dsql/`. DSQL uses
its own embedded migration history, so a clean rebase and compile do not
ensure schema compatibility. Add forward migrations rather than changing a
baseline that production has already applied. Keep DDL and backfill DML in
separate migrations with `run_in_transaction = false`.

For the 1.37.5 migrations, run the populated-table, non-UTC backfill and
old-version-insert regression test against a local PostgreSQL server (it uses
connection-local temporary tables). The policy revision column needs a default
before backfilling, because in-flight or rolled-back old instances omit it:

```sh
DSQL_MIGRATION_TEST_DATABASE_URL=postgresql://localhost/vaultwarden_test \
  cargo test --locked --profile ci --features aws \
  release_1_37_5_migrations_preserve_existing_rows -- --ignored
```

The S3 feature deliberately injects Vaultwarden's HTTP client into OpenDAL's
reqwest transport. If the rebase changes OpenDAL, confirm that each S3
operator still receives that transport in an `OperationContext`. A compile
check covers the trait API, but an S3 smoke test is still needed to detect
runtime routing failures. Both the OpenDAL and AWS SDK transports should
continue to use `get_reqwest_client_builder(false)` so they inherit the shared
HTTP policy and standard ten-second deadline.

Refresh the template's `IP_HEADER_TRUSTED_PROXIES` from the current AWS
`ip-ranges.json` entries whose service is `CLOUDFRONT_ORIGIN_FACING` (both IPv4
and IPv6), retaining the adapter loopback addresses. CloudFront and Lambda
Function URLs append addresses to `X-Forwarded-For`; since 1.37.4 Vaultwarden
selects the rightmost untrusted address. Missing edge ranges therefore break
viewer-IP attribution and rate limiting. Never use `all` to avoid maintaining
the list. Check that all Lambda environment keys and values together remain
within the 4 KB limit.

Build from `main`, test the archive, and record its checksum:

```sh
./aws/build-lambda.sh
unzip -t aws/vaultwarden-lambda.zip
shasum -a 256 aws/vaultwarden-lambda.zip
```

Use the release-pinned compiler first. A previous 1.98.1 ARM64 build hit a
metadata-decoder compiler panic; 1.97.1 succeeded as a temporary workaround.
Do not carry that override forward without checking the new release's minimum
Rust version. Preserve full build logs when diagnosing a compiler panic.

The builder uses a minimal Amazon Linux 2023 image, matching the Lambda
runtime. The full CodeBuild image is unnecessary and can consume about
19 GB before any compilation. Check host free space as well as Docker's
virtual disk, and follow `~/devel/dev-machine/disk-pruning.md` before cleanup.
Cargo's Linux target cache stays in a Docker volume named for this checkout,
avoiding large archive writes through Docker's host bind mount. The final ZIP
is still written to `aws/vaultwarden-lambda.zip` on the host. Treat that volume
as a reusable build cache; do not prune other checkouts' volumes.

The build script and its GitHub workflow must invoke `cargo lambda build` with
the `aws` feature. Stop and fix the build configuration if they do not.

Fetch `origin` again immediately before pushing. Publish rebased history only
with explicit leases recorded above; a lease failure means someone else
updated the branch, so stop and reconcile rather than retrying blindly.

```sh
git fetch origin aws-ses main
git push --force-with-lease="aws-ses:${origin_aws_ses}" \
  origin aws-ses:aws-ses
git push --force-with-lease="main:${origin_main}" origin main:main
```

## 5. Create and review the deployment changeset

Confirm AWS identity, stack health, and live versions before mutation:

```sh
aws sts get-caller-identity --profile vaultwarden
aws cloudformation describe-stacks --profile vaultwarden \
  --stack-name vaultwarden
curl -fsS https://vault.chasedouglas.net/api/config
curl -fsS https://vault.chasedouglas.net/vw-version.json
```

Resolve the actual stack name and region from `aws/samconfig.toml` if they are
not `vaultwarden` and `us-east-2`. Do not commit that file merely to perform a
release.

Build the SAM staging directory and create, but do not yet execute, a
changeset. Explicitly override the local `disable_rollback` setting:

```sh
cd aws
sam build
sam deploy --profile vaultwarden --no-execute-changeset \
  --no-confirm-changeset --no-disable-rollback
```

Capture the exact changeset ARN printed by SAM. Inspect it with
`aws cloudformation describe-change-set` and confirm:

- The stack name, account, and region are correct.
- There are no replacements or deletions.
- The expected Lambda code/configuration is the only material runtime change,
  unless the upstream rebase intentionally changed the template.
- Parameter values match the existing stack. No blank local value silently
  replaces a production setting.

Stop if the changeset differs from those expectations.

For a preparation-only request, stop before execution. Retain the Lambda ZIP,
SAM staging directory, verified web-vault archive and extracted assets,
current web-vault rollback copy, and inspected S3 sync dry run. Record their
absolute paths and checksums with the changeset ARN. Do not push rewritten
branches, upload web-vault assets, invalidate CloudFront, or clean up the
prepared artifacts until those actions are authorized.

## 6. Execute and verify the backend

Execute the exact reviewed changeset, wait for completion, and inspect stack
events if it fails:

```sh
aws cloudformation execute-change-set --profile vaultwarden \
  --change-set-name CHANGESET_ARN
aws cloudformation wait stack-update-complete --profile vaultwarden \
  --stack-name vaultwarden
```

Verify that `/api/config` reports the new `main` commit hash and expected
compatibility version. Query recent Lambda logs for startup panics or request
errors. Do not rely on a successful CloudFormation status alone.

## 7. Update the compatible web vault

Extract `vault_version` from `docker/DockerSettings.yaml` on the deployed
`main` branch. Remove its leading `v` only for the JSON version comparison.

Inspect the immutable release and download its tarball, checksum manifest, and
detached signature from `dani-garcia/bw_web_builds`. Verify the entire checksum
manifest before extraction. Reject archives containing absolute paths,
parent-directory traversal, or symlinks.

Resolve current resource IDs:

```sh
aws cloudformation describe-stacks --profile vaultwarden \
  --stack-name vaultwarden
aws cloudformation describe-stack-resource --profile vaultwarden \
  --stack-name vaultwarden --logical-resource-id CDN
```

If the live `vw-version.json` already matches the pinned version, do not
rewrite the bucket. Otherwise:

1. Download the current bucket into a newly created temporary rollback
   directory.
2. Compare the rollback copy with the extracted release by content. Do not
   trust `aws s3 sync` as a byte comparison: a changed file with the same size
   is skipped when the release archive's timestamp is older than S3. Normalize
   timestamps in the temporary extracted copy, or otherwise force every
   content difference to appear in the dry run.
3. Run `aws s3 sync ... --delete --dryrun` and inspect uploads and deletions.
4. Sync the extracted `web-vault/` directory with `--delete`.
5. Repeat the dry run with `--size-only`; it must report no changes. Download
   the resulting bucket into a separate temporary directory and compare the
   complete directory with the extracted release byte for byte.
6. Invalidate `/*` on the resolved CloudFront distribution and wait for it.
7. Verify the public version marker, `index.html`, primary JavaScript bundle,
   and WASM module against the release artifact byte for byte.

Keep the rollback directory until all live checks succeed. Never use a bucket
name or distribution ID copied from an earlier release.

## 8. Finish and clean up

Record:

- Release tag and commit.
- New `aws-ses` and `main` tips.
- Lambda package SHA-256.
- CloudFormation changeset ARN and final stack status.
- Backend compatibility version and live `gitHash`.
- Pinned and live web-vault versions.
- CloudFront invalidation ID, if one was needed.
- Any verification that could not be performed.

After successful verification, remove only generated artifacts and temporary
directories created by this run, including `target/`, `aws/.aws-sam/`, the
Lambda ZIP, downloaded web-vault files, and rollback copies. Do not delete
operator files or prune shared Docker caches unless the user separately asks
for that cleanup.

If production verification fails, retain rollback material, stop cleanup, and
report the exact failure. Use the backup branches for source recovery. Restore
the previous Lambda package or web-vault bucket contents only with explicit
authorization for that rollback.
