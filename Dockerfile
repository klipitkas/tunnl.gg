# Build stage (pinned by digest; update the tag and digest together)
FROM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Version info logged at startup
ARG VERSION=dev
ARG COMMIT=unknown

# Build with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -trimpath \
    -o tunnl \
    ./cmd/tunnl

# Runtime stage - use scratch for smallest possible image
FROM scratch

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /app/tunnl /tunnl

# Expose ports
# 22: SSH (tunnel connections)
# 80: HTTP (ACME challenges + redirect)
# 443: HTTPS (tunnel traffic)
EXPOSE 22 80 443

# Run as non-root (UID 65534 = nobody)
USER 65534:65534

ENTRYPOINT ["/tunnl"]
