FROM rust:1.91-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release --bin meshx-relay-server

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data meshx \
    && mkdir -p /data \
    && chown -R meshx:meshx /data
COPY --from=build /app/target/release/meshx-relay-server /usr/local/bin/meshx-relay-server
USER 10001:10001
ENV MESHX_RELAY_KEY_FILE=/data/relay-identity.key
ENV MESHX_RELAY_LISTEN=/ip4/0.0.0.0/tcp/4001
EXPOSE 4001/tcp
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/meshx-relay-server"]
