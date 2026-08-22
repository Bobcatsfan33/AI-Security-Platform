ARG GO_IMAGE=golang:1.26.7-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468
FROM ${GO_IMAGE} AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w" \
    -o /out/agent \
    ./cmd/agent

FROM scratch AS runtime
ARG GO_IMAGE
LABEL org.opencontainers.image.base.name="scratch" \
      org.opencontainers.image.build.base.name="${GO_IMAGE}"
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/agent /agent
USER 65532:65532
EXPOSE 8400 8401
ENTRYPOINT ["/agent"]
