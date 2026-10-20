FROM php:8.3-cli

WORKDIR /app
COPY . .

CMD ["sh", "-c", "php -S 0.0.0.0:${PORT:-8080} -t /app"]
