# === Etapa 1: build do binário ===
FROM golang:1.24.5-alpine AS builder

# instala compilador C e musl-dev para CGO
RUN apk add --no-cache gcc musl-dev

# ativa CGO
ENV CGO_ENABLED=1

WORKDIR /app
COPY . .

RUN go mod download && \
    go build -o rotacerta ./cmd

# === Etapa 2: imagem final leve ===
FROM alpine:3.20
WORKDIR /app
COPY --from=builder /app/rotacerta /usr/bin/rotacerta

EXPOSE 8080
CMD ["rotacerta"]
