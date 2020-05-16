FROM rockylinux/rockylinux:8
RUN yum install -y epel-release
RUN yum install -y openssl-devel copr-cli
RUN yum groupinstall -y 'Development Tools'
ARG toolchain
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${toolchain}
ENV PATH=/root/.cargo/bin:$PATH
RUN cargo install cargo-rpm
COPY . /root/src
WORKDIR /root/src/
