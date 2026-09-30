# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/secmail ./cmd/secmail \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mock-analyzer ./cmd/mock-analyzer

# Alpine (not distroless) because outbound DLP shells out to Tesseract (OCR,
# Korean + English), libheif (HEIC/AVIF) and poppler (JBIG2/JPEG2000 scans,
# restricted PDFs).
FROM alpine:3
RUN apk add --no-cache ca-certificates tzdata tesseract-ocr tesseract-ocr-data-kor tesseract-ocr-data-eng \
      libheif-tools poppler-utils \
 && adduser -D -H -u 65532 nonroot
COPY --from=build /out/secmail /out/mock-analyzer /usr/local/bin/
USER nonroot
EXPOSE 2525 8080 8081
ENTRYPOINT ["/usr/local/bin/secmail"]
CMD ["-config", "/etc/secmail/config.yaml"]
