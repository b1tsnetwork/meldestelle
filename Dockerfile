# syntax=docker/dockerfile:1
# Das Binary wird auf der Build-Plattform für die Zielplattform cross-kompiliert (reines Go, kein CGO),
# daher sind Multi-Arch-Images ohne QEMU-Emulation schnell gebaut.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/meldestelle . \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/meldestelle /meldestelle
COPY --from=build --chown=65532:65532 /out/data /data
ENV MS_DATA_DIR=/data \
    MS_LISTEN=:8080 \
    TZ=Europe/Berlin
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/meldestelle", "healthcheck"]
ENTRYPOINT ["/meldestelle"]
CMD ["serve"]
