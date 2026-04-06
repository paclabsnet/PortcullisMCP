# syntax=docker/dockerfile:1

# Stage 1: build all binaries
FROM golang:1.26.1-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0-dev
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/paclabsnet/PortcullisMCP/internal/version.Version=${VERSION}" -o /out/portcullis-gate   ./cmd/portcullis-gate
RUN CGO_ENABLED=0 go build -ldflags "-X github.com/paclabsnet/PortcullisMCP/internal/version.Version=${VERSION}" -o /out/portcullis-keep   ./cmd/portcullis-keep
RUN CGO_ENABLED=0 go build -o /out/mock-enterprise-api ./examples/mock-enterprise-api
RUN CGO_ENABLED=0 go build -o /out/fetch-mcp           ./examples/fetch-mcp

# Stage 2: portcullis-gate
FROM gcr.io/distroless/static:nonroot AS gate
COPY --from=builder /out/portcullis-gate /portcullis-gate
ENTRYPOINT ["/portcullis-gate"]

# Stage 3: portcullis-keep
FROM gcr.io/distroless/static:nonroot AS keep
COPY --from=builder /out/portcullis-keep /portcullis-keep
ENTRYPOINT ["/portcullis-keep"]

# Stage 4: mock-enterprise-api
FROM gcr.io/distroless/static:nonroot AS mock-enterprise-api
COPY --from=builder /out/mock-enterprise-api /mock-enterprise-api
ENTRYPOINT ["/mock-enterprise-api"]

# Stage 5: fetch-mcp
FROM gcr.io/distroless/static:nonroot AS fetch-mcp
COPY --from=builder /out/fetch-mcp /fetch-mcp
ENTRYPOINT ["/fetch-mcp"]
