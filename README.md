# Cloud.ru Evolution S3 Reverse Proxy

Прокси-сервер для прозрачной миграции с MinIO на Cloud.ru Evolution Object Storage.
Проверяет входящую подпись AWS SigV4 (ключи MinIO) и переподписывает запрос ключами Cloud.ru.

## Запуск

1. Укажите ваши ключи в `docker-compose.yml`:
   - `MINIO_ACCESS_KEY` и `MINIO_SECRET_KEY` — старые учетные данные клиентов.
   - `CLOUD_ACCESS_KEY` (в формате `<tenant_id>:<key_id>`) и `CLOUD_SECRET_KEY` — ключи от Cloud.ru Evolution.
2. Соберите и запустите контейнер:
   ```bash
   docker compose up -d --build
   ```
3. Проверьте логи:
   ```bash
   docker logs -f s3-proxy
   ```

# Проверить
постоянные обращения на
2026/11/20 04:02:20 [PROXY] GET /health-check?location
2026/11/20 04:02:20 [PROXY] HEAD /triton-model-repository
2026/11/20 04:02:20 [PROXY] GET /triton-model-repository?list-type=2&prefix=staging%2Fsmart-autoresp%2F