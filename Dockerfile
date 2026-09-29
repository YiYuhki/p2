# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/secmail ./cmd/secmail \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mock-analyzer ./cmd/mock-analyzer

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/secmail /out/mock-analyzer /usr/local/bin/
USER nonroot
EXPOSE 2525 8080 8081
ENTRYPOINT ["/usr/local/bin/secmail"]
CMD ["-config", "/etc/secmail/config.yaml"]
