FROM rust:1.86-bookworm AS builder
WORKDIR /work

COPY . .
RUN cargo build --release -p inactu-control

FROM debian:bookworm-slim
RUN useradd --create-home --shell /usr/sbin/nologin appuser
WORKDIR /app

COPY --from=builder /work/target/release/inactu-control /usr/local/bin/inactu-control

ENV INACTU_CONTROL_BIND=0.0.0.0:8080
EXPOSE 8080
USER appuser

CMD ["inactu-control"]
