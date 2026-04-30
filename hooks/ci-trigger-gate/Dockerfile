FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /ci-trigger-gate .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /ci-trigger-gate /usr/local/bin/ci-trigger-gate
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["ci-trigger-gate"]
