FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /debug-bundle .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl \
    && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl \
    && rm kubectl
COPY --from=builder /debug-bundle /usr/local/bin/debug-bundle
RUN mkdir -p /tmp/bundles && chown 65532:65532 /tmp/bundles
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["debug-bundle"]
