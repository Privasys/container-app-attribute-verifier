# The Privasys Attribute Verifier, built as a reproducible single-binary
# image. Nothing is generated at first boot except key material on the
# sealed volume, so the image the platform measures is the whole of what
# runs. Single-arch and provenance-free on purpose: an OCI attestation
# index would change the manifest digest the enclave pins at
# OID 1.3.6.1.4.1.65230.3.2.

FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/attribute-verifier ./cmd/attribute-verifier

# The verifier talks outward over HTTPS only: provider key sets, GitHub's
# API, Microsoft Graph for mail, and the Privasys back office. It needs a
# trust store and nothing else.
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/attribute-verifier /usr/local/bin/attribute-verifier
# The manifest, served at GET /.well-known/privasys-manifest so a client
# reads the tool contract over the attested channel. CI also embeds it as
# the org.privasys.manifest label.
COPY privasys.json /privasys.json

LABEL org.privasys.config_api="POST /configure"
LABEL org.opencontainers.image.source="https://github.com/Privasys/container-app-attribute-verifier"
LABEL org.opencontainers.image.title="Privasys Attribute Verifier"
LABEL org.opencontainers.image.description="Checks the evidence behind a wallet attribute and signs a proof"

# No fixed port and no EXPOSE: the platform injects a unique $PORT.
ENTRYPOINT ["/usr/local/bin/attribute-verifier"]
