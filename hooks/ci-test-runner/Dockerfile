FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /ci-test-runner .

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=builder /ci-test-runner /usr/local/bin/ci-test-runner
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["ci-test-runner"]
