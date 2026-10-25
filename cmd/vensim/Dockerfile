# Test-only image of the VENS scanner simulator (cmd/vensim) for the
# isolated version matrix of ScanSnap Control (tests/matrix/). Never part
# of the production image: the root Dockerfile builds the airscap command
# only. Bind the control API to a test network; it has no authentication.
#
#   git archive <commit> | docker build -f cmd/vensim/Dockerfile -t vensim-matrix:a2 -
FROM golang:1.26.0-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go mod vendor && go mod verify \
 && CGO_ENABLED=0 go build -mod=vendor -overlay=build/overlay.json -trimpath -o /out/vensim ./cmd/vensim

FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /out/vensim /usr/local/bin/vensim
ENTRYPOINT ["/usr/local/bin/vensim"]
