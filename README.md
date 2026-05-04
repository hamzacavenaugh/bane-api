# bane-api

Backend for **Bane Performance Peptides** — admin auth, orders, reviews, coupons, analytics, image picker.

The static front-end lives separately on SiteGround (`cavenaughm20.sg-host.com`) and calls this API cross-origin.

## Run

```bash
npm install
npm start
```

Listens on `process.env.PORT || 3000`.

## Env vars

| Var | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | HTTP port |
| `NODE_ENV` | — | Set to `production` to enable secure cookies + trust-proxy + cache headers |
| `ADMIN_EMAIL` | `support@baneperformance.com` | Seeded admin email on first boot |
| `ADMIN_PASSWORD` | `BanePerf!2026` | Seeded admin password on first boot |
| `SESSION_SECRET` | random per-boot | Cookie signing key. Set this in prod so sessions survive restarts |
| `ALLOWED_ORIGINS` | `localhost:3000,cavenaughm20.sg-host.com` | Comma-separated list of origins that may call the API |

## Persistence note

Data is written to `data/bane.json`. Render free tier filesystems are **ephemeral** — every restart/redeploy wipes orders, reviews, coupons, custom products, and logged-in sessions. For real production use, attach a Render disk ($1/mo) or migrate to Postgres.
