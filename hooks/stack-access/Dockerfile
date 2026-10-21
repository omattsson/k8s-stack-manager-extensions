# Cross-compile on the build platform: client-go is slow to build under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /stack-access .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /stack-access /usr/local/bin/stack-access
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["stack-access"]
