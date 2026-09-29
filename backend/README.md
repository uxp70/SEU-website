# SEU backend

Zero-dependency Node auth API for the SEU website.

Endpoints: `POST /api/login`, `GET /api/me`, `POST /api/logout`,
`GET /api/home` (gated), `GET /api/health`.

## Run locally

Set env from `.env.example`, then:

```
node server.js
```

## Deploy (Render free)

1. Push this repo to GitHub.
2. Render > New > Web Service > select repo, root `backend`.
3. Set env: `SEU_PASSWORD_HASH` (sha256 hex of password),
   `SEU_SECRET` (long random string),
   `ALLOWED_ORIGINS=https://seuhq.dpdns.org`.
4. After deploy, add DNS `api.seuhq.dpdns.org` CNAME to your
   Render URL, and set frontend `API_BASE` in `index.html`
   to `https://api.seuhq.dpdns.org`.
