FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /security-scan-gate .

FROM aquasec/trivy:latest AS trivy

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /security-scan-gate /usr/local/bin/security-scan-gate
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["security-scan-gate"]
