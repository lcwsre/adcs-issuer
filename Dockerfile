# Build the manager binary
# Option 1: Pre-built binary (fast) - build locally first:
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-w -s' -trimpath -o manager main.go
# Option 2: Build inside Docker (slow but self-contained) - uncomment the builder stage below

# Use distroless as minimal base image to package the manager binary
FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.source="https://github.com/lcwsre/adcs-issuer" \
      org.opencontainers.image.description="ADCS Issuer for cert-manager" \
      org.opencontainers.image.licenses="BSD-3-Clause"

WORKDIR /
COPY manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
