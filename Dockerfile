# builder image
FROM golang:1.19-alpine
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o /bin/ciscollector ./cmd/ciscollector/main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /app/
COPY --from=builder /bin/ciscollector /app/ciscollector
ENTRYPOINT ["/app/ciscollector"]
