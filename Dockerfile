FROM golang:1.25.10-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS
ARG TARGETARCH

RUN set -eux; \
    os="${TARGETOS:-linux}"; \
    arch="${TARGETARCH:-amd64}"; \
    ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"; \
    CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build -trimpath -ldflags "${ldflags}" -o /out/continuum ./cmd/continuum; \
    CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build -trimpath -ldflags "${ldflags}" -o /out/continuum-agent ./cmd/continuum-agent

FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="Continuum" \
      org.opencontainers.image.description="Governed capability fabric for observe-mode machine workloads" \
      org.opencontainers.image.source="https://github.com/M31-Labs/continuum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/continuum /usr/local/bin/continuum
COPY --from=build /out/continuum-agent /usr/local/bin/continuum-agent

WORKDIR /work
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/continuum"]
CMD ["version"]
