# AirScap for ScanSnap Control on the QNAP (docs/lan-deployment.md).
# Go binary without cgo; OCR stays off. The binary is still dynamically
# linked (purego from the ONNX dependency), so the runtime needs glibc:
# distroless/base, not distroless/static. The service UID is set by compose
# and must own the shared intake directory.
FROM golang:1.26.0-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go mod vendor && go mod verify \
 && CGO_ENABLED=0 go build -mod=vendor -overlay=build/overlay.json -trimpath \
      -ldflags="-s -w" -o /out/airscap ./cmd/airscap

FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /out/airscap /usr/local/bin/airscap
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/airscap"]
