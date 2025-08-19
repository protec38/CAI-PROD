# Redirect loop fix (ERR_TOO_MANY_REDIRECTS)

This build trusts your reverse proxy (Cloudflare/Nginx/Traefik) for HTTPS via:
- `werkzeug.middleware.proxy_fix.ProxyFix`
- Gunicorn `--forwarded-allow-ips='*'`
- `FORCE_HTTPS=1` to keep HTTPS redirection via Flask-Talisman

If your proxy does **not** set `X-Forwarded-Proto: https`, you can disable forced HTTPS quickly:
- Edit `.env` and add `FORCE_HTTPS=0` (compose already passes it through)
  or set it in `docker-compose.yml`.
- Then `docker compose up -d`.

Tip: Ensure your proxy sends:
  - `X-Forwarded-Proto: https`
  - `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Port`
