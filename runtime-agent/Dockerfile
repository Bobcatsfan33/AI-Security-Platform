ARG GO_IMAGE=golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2
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
