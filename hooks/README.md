The hooks in this directory are used to create multi-arch images using Docker Hub automated builds.

Docker Hub hooks provide these predefined [environment variables](https://docs.docker.com/docker-hub/builds/advanced/#environment-variables-for-building-and-testing):

* `SOURCE_BRANCH`: the name of the branch or the tag that is currently being tested.
* `SOURCE_COMMIT`: the SHA1 hash of the commit being tested.
* `COMMIT_MSG`: the message from the commit being tested and built.
* `DOCKER_REPO`: the name of the Docker repository being built.
* `DOCKERFILE_PATH`: the dockerfile currently being built.
* `DOCKER_TAG`: the Docker repository tag being built.
* `IMAGE_NAME`: the name and tag of the Docker repository being built. (This variable is a combination of `DOCKER_REPO:DOCKER_TAG`.)

The current multi-arch image build relies on the original vaultwarden Dockerfiles, which use cross-compilation for architectures other than `amd64`, and don't yet support all arch/distro combinations. However, cross-compilation is much faster than QEMU-based builds (e.g., using `docker buildx`). This situation may need to be revisited at some point.

## References

* https://docs.docker.com/docker-hub/builds/advanced/
* https://docs.docker.com/engine/reference/commandline/manifest/
* https://www.docker.com/blog/multi-arch-build-and-images-the-simple-way/
* https://success.docker.com/article/how-do-i-authenticate-with-the-v2-api
