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
FROM registry.access.redhat.com/ubi9-minimal:9.8@sha256:beeada7dd17903dfb69fd5f6916c054720bf28a52daaa2f7a1910a1394244bd2
WORKDIR /
RUN mkdir /.bitcoin
RUN touch /.bitcoin/alert_system_private_key
COPY --from=builder /opt/app-root/src/go-alert-system .
USER 65534:65534
ENV ALERT_SYSTEM_ENVIRONMENT=local
CMD ["/go-alert-system"]
