FROM galtbv/builder:ubi9@sha256:a4d5adae0cb776574255bf1c326583fcbd9560275c81572b0283fea90e33bec4 AS builder

# Copy in the go src
WORKDIR $APP_ROOT/src/github.com/bsv-blockchain/go-alert-system
COPY app/    app/
COPY cmd/    cmd/
COPY utils/ utils/
COPY go.mod go.mod
COPY go.sum go.sum
RUN CGO_ENABLED=0 go build -a -o $APP_ROOT/src/go-alert-system github.com/bsv-blockchain/go-alert-system/cmd/go-alert-system

# Copy the controller-manager into a thin image
FROM registry.access.redhat.com/ubi9-minimal:9.8@sha256:c4c285d42941ebb2bd4da878479008e1e4536bb599aad1dbe568f89de9053661
WORKDIR /
# The p2p private key is generated here on first start; mount a volume at /.bitcoin to keep the peer ID across restarts
RUN mkdir /.bitcoin && chown 65534:65534 /.bitcoin && chmod 700 /.bitcoin
COPY --from=builder /opt/app-root/src/go-alert-system .
USER 65534:65534
ENV ALERT_SYSTEM_ENVIRONMENT=local
CMD ["/go-alert-system"]
