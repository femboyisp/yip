# Multi-stage production Dockerfile for yip suite

# Stage 1: Builder
FROM rust:alpine AS builder

# Install build essentials required for compiling C/C++ dependencies and BoringSSL
RUN apk add --no-cache musl-dev gcc g++ make linux-headers git cmake perl clang-dev

ENV LIBCLANG_PATH=/usr/lib
ENV RUSTFLAGS="-C target-feature=-crt-static"

WORKDIR /usr/src/yip

# Copy workspace manifests and source code
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bin ./bin

# Build release binaries and place them into /usr/local/bin
RUN cargo build --release --bin yipd --bin yip-ca --bin yip-rendezvous && \
    cp target/release/yipd /usr/local/bin/yipd && \
    cp target/release/yip-ca /usr/local/bin/yip-ca && \
    cp target/release/yip-rendezvous /usr/local/bin/yip-rendezvous

# Stage 2: yipd
FROM alpine:latest AS yipd

RUN apk add --no-cache ca-certificates libstdc++

COPY --from=builder /usr/local/bin/yipd /usr/local/bin/yipd
COPY --from=builder /usr/local/bin/yip-ca /usr/local/bin/yip-ca

RUN mkdir -p /etc/yip /run/yipd

VOLUME ["/etc/yip", "/run/yipd"]

ENTRYPOINT ["/usr/local/bin/yipd"]
CMD ["/etc/yip/yipd.conf"]

# Stage 3: yip-rendezvous
FROM alpine:latest AS yip-rendezvous

RUN apk add --no-cache ca-certificates libstdc++

COPY --from=builder /usr/local/bin/yip-rendezvous /usr/local/bin/yip-rendezvous
COPY --from=builder /usr/local/bin/yip-ca /usr/local/bin/yip-ca

ENTRYPOINT ["/usr/local/bin/yip-rendezvous"]
