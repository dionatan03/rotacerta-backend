# === Etapa 1: build do binário ===
FROM golang:1.24.5-alpine AS builder
WORKDIR /app
# copia todos os arquivos do seu projeto
COPY . .
# baixa dependências e compila
RUN go mod download && \
    go build -o rotacerta ./cmd

# === Etapa 2: imagem final leve ===
FROM alpine:3.20
WORKDIR /app
# copia só o binário compilado
COPY --from=builder /app/rotacerta /usr/bin/rotacerta
# expõe a porta que seu app usa
EXPOSE 8080
# comando padrão ao iniciar o container
CMD ["rotacerta"]