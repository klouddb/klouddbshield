# syntax=docker/dockerfile:1

FROM golang:1.22-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN rm -rf cmd/main-server/dist && cp -R front cmd/main-server/dist && rm -rf cmd/main-server/dist/design-prototype
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/main-server ./cmd/main-server

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/main-server /app/main-server
COPY docker_testing/e2e/main-server/entrypoint.sh /app/entrypoint.sh
COPY docker_testing/e2e/main-server/seed-guc-baseline.sh /app/seed-guc-baseline.sh
COPY docker_testing/e2e/main-server/server-node.yaml /app/server-node.yaml
COPY docker_testing/e2e/guc-baseline.json /app/guc-baseline.json

RUN chmod +x /app/main-server /app/entrypoint.sh /app/seed-guc-baseline.sh

EXPOSE 8081
ENTRYPOINT ["/app/entrypoint.sh"]
