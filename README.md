
## Honeypot deployment scope

This project is being shaped into a web honeypot and assumes **deployment on a dedicated honeypot host or subdomain**, not alongside a real production application.

- Set `HONEYPOT_ALLOWED_HOSTS` to the exact hostnames that should serve the honeypot, for example `honeypot.example.com`.
- Keep `HONEYPOT_ENFORCE_HOST=true` in deployed environments so requests on unexpected hosts receive a plain `404`.
- Set `HONEYPOT_OPERATOR_TOKEN` before exposing the internal operator dashboard under `/{HONEYPOT_OPERATOR_PATH_PREFIX}`.
- Honeypot uploads are quarantined on the `honeypot-quarantine` disk under `storage/app/honeypot/quarantine`.
- For local development, keep `APP_URL` and `HONEYPOT_ALLOWED_HOSTS` aligned, such as `localhost`.

This host guard is the first containment control: it reduces the risk of accidentally exposing honeypot behavior on the wrong virtual host before deeper deception features are added.

## Honeypot MVP features

- Captures request method, host, path, headers, query, payload preview, response status, techniques, and session grouping.
- Returns deceptive responses for probes such as `/.env`, admin/login panels, backup files, and common Laravel / WordPress exploit paths.
- Quarantines uploaded files outside the public web root.
- Exposes an operator dashboard behind a token-protected route and provides scheduled daily summaries plus retention cleanup commands.

## Useful commands

```bash
php artisan migrate
php artisan honeypot:daily-summary
php artisan honeypot:purge-stale-data
composer test
```
