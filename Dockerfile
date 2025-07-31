FROM golang:1.24.5-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download && go build -o rotacerta ./cmd

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/rotacerta /usr/bin/rotacerta
EXPOSE 8080
CMD ["rotacerta"]

