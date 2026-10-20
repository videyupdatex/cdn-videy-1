FROM php:8.3-cli

WORKDIR /app
COPY . .

# index.php dipakai sebagai router: semua URL (termasuk /ID.mp4) diproses index.php
CMD ["sh", "-c", "php -S 0.0.0.0:${PORT:-8080} -t /app /app/index.php"]
