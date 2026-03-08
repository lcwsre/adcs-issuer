# Build the manager binary
# Multi-stage build (requires internet access from Docker):
#   docker build -t lcwsre/adcs-issuer:latest .
#
# If your environment has proxy/TLS issues, build locally first:
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-w -s' -trimpath -o manager main.go
#   docker build --target production -t lcwsre/adcs-issuer:latest .

# --- Builder stage ---
FROM golang:1.26 AS builder
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY main.go main.go
COPY api/ api/
COPY controllers/ controllers/
COPY adcs/ adcs/
COPY issuers/ issuers/
COPY healthcheck/ healthcheck/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-w -s' -trimpath -o manager main.go

# --- Production stage ---
FROM gcr.io/distroless/static:nonroot AS production

LABEL org.opencontainers.image.source="https://github.com/lcwsre/adcs-issuer" \
      org.opencontainers.image.description="ADCS Issuer for cert-manager" \
      org.opencontainers.image.licenses="BSD-3-Clause"

WORKDIR /
COPY manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
