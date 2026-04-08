# syntax=docker/dockerfile:1

# Stage 1: build all binaries
FROM golang:1.26.1-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.4.2-dev
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/paclabsnet/PortcullisMCP/internal/version.Version=${VERSION}" -o /out/portcullis-gate   ./cmd/portcullis-gate
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/paclabsnet/PortcullisMCP/internal/version.Version=${VERSION}" -o /out/portcullis-keep   ./cmd/portcullis-keep
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/paclabsnet/PortcullisMCP/internal/version.Version=${VERSION}" -o /out/portcullis-guard  ./cmd/portcullis-guard
RUN CGO_ENABLED=0 go build -o /out/mock-enterprise-api ./examples/mock-enterprise-api
RUN CGO_ENABLED=0 go build -o /out/fetch-mcp           ./examples/fetch-mcp

# Stage 2: portcullis-keep
FROM gcr.io/distroless/static:nonroot AS keep
COPY --from=builder /out/portcullis-keep /portcullis-keep
ENTRYPOINT ["/portcullis-keep"]

# Stage 3: portcullis-guard (needs HTML templates)
FROM gcr.io/distroless/static:nonroot AS guard
COPY --from=builder /out/portcullis-guard /portcullis-guard
COPY internal/guard/templates /templates
ENTRYPOINT ["/portcullis-guard"]

# Stage 4: mock-enterprise-api
FROM gcr.io/distroless/static:nonroot AS mock-enterprise-api
COPY --from=builder /out/mock-enterprise-api /mock-enterprise-api
ENTRYPOINT ["/mock-enterprise-api"]

# Stage 5: fetch-mcp
FROM gcr.io/distroless/static:nonroot AS fetch-mcp
COPY --from=builder /out/fetch-mcp /fetch-mcp
ENTRYPOINT ["/fetch-mcp"]
