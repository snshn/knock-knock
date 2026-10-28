# Apify Actor image for knock-knock
# (built with the repository root as context, see dockerContextDir in actor.json)

FROM rust:1-slim-bookworm AS builder

# perl and make are needed for building vendored OpenSSL, cmake for aws-lc
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake make perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --release --locked


FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates jq \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global apify-cli \
    && npm cache clean --force

COPY --from=builder /src/target/release/knock-knock /usr/local/bin/knock-knock
COPY .actor/main.sh /usr/local/bin/knock-knock-actor

USER node

CMD ["/usr/local/bin/knock-knock-actor"]
