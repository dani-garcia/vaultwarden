all:
	./render_template Dockerfile.j2 '{"base": "debian"}' > Dockerfile.debian
	./render_template Dockerfile.j2 '{"base": "alpine"}' > Dockerfile.alpine
.PHONY: all
