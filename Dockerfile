FROM rust:1.93-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY crates ./crates
RUN cargo build --locked --release --bin bench_unified

FROM debian:bookworm-slim
COPY --from=build /src/target/release/bench_unified /usr/local/bin/bench_unified
WORKDIR /work
ENTRYPOINT ["bench_unified"]
