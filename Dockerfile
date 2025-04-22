FROM rust:1.86-alpine3.21 AS builder

RUN apk add --no-cache alpine-sdk openssl-dev perl

WORKDIR /app

RUN mkdir -p contracts/icp/src
RUN mkdir -p dvaultd/src

COPY contracts/icp/Cargo.toml contracts/icp
COPY dvaultd/Cargo.toml dvaultd
COPY Cargo.toml Cargo.lock .

RUN echo "fn asd() {}" > contracts/icp/src/lib.rs
RUN echo "fn main() {}" > dvaultd/src/main.rs
RUN cargo build
RUN rm -rf contracts/icp/src
RUN rm -rf dvaultd/src

COPY contracts/icp/src/ contracts/icp/src/
COPY dvaultd/src/ dvaultd/src/
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build



FROM alpine:3.21 AS app
RUN apk add --no-cache alpine-sdk
WORKDIR /root
RUN  apk add --no-cache openssh bash
RUN mkdir /var/run/sshd
RUN ssh-keygen -A
COPY --from=builder /app/target/debug/dvaultd /usr/local/bin/dvaultd
COPY ./entrypoint.sh /root/entrypoint.sh
RUN mkdir data
COPY contracts/icp/.dfx/local/canister_ids.json /usr/local/bin/canister_ids.json
ENTRYPOINT ["/root/entrypoint.sh"]
