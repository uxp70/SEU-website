# SEU website

Homescreen for `seuhq.dpdns.org`, hosted with GitHub Pages.

## Deploy
1. Push this folder to GitHub as `SEU-website` (or any name).
2. In repo: Settings > Pages > Deploy from branch > `main` / `/ (root)`.
3. Custom domain should auto-fill as `seuhq.dpdns.org` from `CNAME`. If not, enter it manually and Enforce HTTPS.
4. At your dpdns provider, add:
   - `seuhq` CNAME -> `<username>.github.io.` (recommended)
   - Or A records to GitHub Pages IPs if apex is required.
5. Wait for DNS + certificate check to go green.
