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
FROM registry.access.redhat.com/ubi9-minimal:9.7@sha256:7d4e47500f28ac3a2bff06c25eff9127ff21048538ae03ce240d57cf756acd00
WORKDIR /
RUN mkdir /.bitcoin
RUN touch /.bitcoin/alert_system_private_key
COPY --from=builder /opt/app-root/src/go-alert-system .
USER 65534:65534
ENV ALERT_SYSTEM_ENVIRONMENT=local
CMD ["/go-alert-system"]
