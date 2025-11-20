FROM rust:1.91-bullseye
ENV DEBIAN_FRONTEND=noninteractive

# Install OS deps needed for building some crates
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        build-essential \
        ca-certificates \
        curl && \
    rm -rf /var/lib/apt/lists/*

# Install cargo tools (compiled into the image so subsequent runs are fast)
RUN /usr/local/cargo/bin/cargo install cargo-audit cargo-deny

WORKDIR /workspace

CMD ["bash"]
