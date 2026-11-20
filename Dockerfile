FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -ldflags="-s -w" -o /app/s3-proxy main.go

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/s3-proxy /usr/local/bin/s3-proxy
EXPOSE 7070
ENTRYPOINT ["/usr/local/bin/s3-proxy"]
