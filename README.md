# threatintel-platform

A self-hosted, open-source threat intelligence platform built for the Kenyan Government and Financial Sector. Crawls .onion networks, monitors Telegram channels, tracks ransomware groups, profiles threat actors, and delivers a daily intelligence digest — all from a single Docker Compose deployment.

**Version: 1.1.0 · License: AGPL-3.0**

---

## Features (Verified Working)

- **Dark Web Crawler** — async Tor-based crawler for .onion sites with configurable Kenyan keyword monitoring.
- **Telegram Channel Monitor** — on-demand scraping of public Telegram OSINT channels (StringSession auth, Stop Scan support, ZIP export). Keyword hits persist to the threat hits database.
- **Threat Intelligence REST API v1** — read-only API at `/api/v1/*` with 14 endpoints authenticated via `X-API-Key` header. See `API.md`.
- **STIX 2.1 Export** — `/api/v1/export/stix` returns up to 100 latest IOCs as STIX 2.1 indicator objects for MISP/Splunk/TheHive ingest.
- **Webhook Alerting** — `/api/v1/alerts/test` and crawler hits POST to a configurable `ALERT_WEBHOOK_URL` (Slack/Teams/Discord).
- **Suricata IDS Integration** — custom DDoS rules (HTTP/HTTPS/ICMP flood), `eve.json` parser running as a background thread every 15 s, hits stored in the same threat hits table and shown on the "Network Alerts" dashboard tab.
- **KE-CIRT Advisory Ingestion** — automated ingestion of KE-CIRT/CC, CAK, and CBK PDF advisories (`data/ke_reports/`) into the `ke_cirt_advisories` table with date extraction, summary cleaning, and a dashboard tab.
- **Fintech IOC Correlation Engine** — `/api/v1/fintech/watchlist`, `/api/v1/fintech/lookup`, `/api/v1/fintech/flagged`. Real-world IOC watchlist that financial SOCs query to check suspicious IPs/phones against dark web and KE-CIRT intel.
- **Audit Log** — `audit_log` table + `/api/v1/audit` endpoint + dashboard tab. Every STIX export, webhook send, and report download is logged with actor, IP, and user-agent.
- **Sector Filtering** — `/api/v1/threats?sector=fintech|government|banking` and a dashboard dropdown to isolate threats by sector.
- **Self-Registration with Verification** — bcrypt passwords, email verification via Resend API, and admin approval workflow. `/admin/pending_users` for admin approval.
- **KE-CIRT STIX Sharing** — `scripts/push_to_ke_cirt.py` posts the STIX bundle to a configurable `KE_CIRT_WEBHOOK_URL` for outbound intelligence sharing.
- **Production Suricata Override** — `docker-compose.prod.suricata.yml` uses `network_mode: host` for institutional perimeter deployment.
- **DNS Reconnaissance** — passive subdomain enumeration, A/NS/MX record lookups, ASN geolocation, and subdomain graph visualization. Note: active port scans and directory enumeration require network-level access to the target; from a typical internet-connected laptop, they will return 0 results because the target's firewall blocks the requests — this is expected real-world behavior, not a bug.

## Verified as of October 29, 2026

All features under "Features (Verified Working)" have been tested end-to-end on a Docker Compose deployment. Every listed endpoint has been verified with `curl` against a live API key. The "Roadmap" section lists features that are NOT in the current build.

## Roadmap (Planned, Not Implemented)

- Quick Scan (on-demand OSINT sweep)
- Full DNS Investigation suite (Playwright-rendered world map PDF export, aggressive brute-force at scale)
- ransomware.live PRO negotiation-chat / YARA / SEC 8-K UI panels
- WhastMyName username check
- Projects (scoped monitoring engagements)
- Daily Digest (Mailgun morning email)
- 2FA / OAuth end-to-end (code exists in auth.py, untested in CI)
- webcheck sidecar service

---

## Security Posture

- **safe\_fetch with host allowlist and IP blocklist** — all outbound proxy calls go through a hardened HTTP client that enforces HTTPS, TLS verification, a per-host allowlist, and an IP blocklist covering loopback, RFC 1918, link-local, and IPv4-mapped IPv6 ranges; redirects are re-validated per hop
- **DNS rebinding note** — safe\_fetch performs a pre-flight IP check followed by a standard requests connect; a low-TTL rebind between the two resolutions can still reach private IPs on the dns\_crawler recon path (see SECURITY\_REVIEW\_FABLE.md finding 2/3 for details and planned remediation)
- **Non-root containers** — the app container runs as uid 1000 (appuser); the Tor sidecar runs as debian-tor
- **TLS verification** — `verify=True` enforced on all safe\_fetch calls; legacy `ssl.CERT_NONE` paths in dns\_crawler are documented as lower-trust
- **Healthcheck** — dashboard container exposes a Docker healthcheck at `GET /`; nginx depends on it
- **Secret key enforcement** — Flask refuses to start if `DASHBOARD_SECRET_KEY` is absent or set to the placeholder value
- **HTML escaping** — all keyword hit context is escaped before inclusion in alert emails

---

## Architecture

```
docker-compose
  postgres:16-alpine       ← persistent storage (named volume)
  tor                      ← SOCKS5 proxy + control port; runs as debian-tor
  dashboard                ← Flask app; runs as appuser (uid 1000)
  nginx                    ← SSL reverse proxy; Let's Encrypt or self-signed
```

All external API calls (ransomware.live, ThreatFox, AbuseIPDB, VirusTotal, etc.) go over the clearnet. Only `.onion` crawling is Tor-routed.

SQLAlchemy sessions are request-scoped via Flask `g` and torn down at request end, reducing connection pool pressure.

N+1 queries on the ransomware groups and threat actors endpoints have been collapsed: all keyword hit counts are fetched in a single query and merged in Python.

---

## Deployment

### Requirements

- Fresh Linux server (Ubuntu 22.04/24.04 recommended)
- 2 GB RAM minimum (Playwright/Chromium for PDF map rendering requires headroom)
- Ports 80 and 443 open
- A domain name (optional — self-signed SSL works for LAN/VPS access)

### Quick deploy

```bash
curl -fsSL https://raw.githubusercontent.com/mwenda-cpu/kenyan-threatintelligence-platform/main/deploy.sh \
  -o /tmp/deploy.sh && sudo bash /tmp/deploy.sh
```

With a domain and Let's Encrypt SSL:

```bash
DOMAIN=intel.yourdomain.com SSL_EMAIL=you@example.com \
  sudo bash /tmp/deploy.sh
```

The script installs Docker, clones the repo, generates secrets, configures Tor, and starts all services.

### First-time setup after deploy

1. Visit `https://YOUR_SERVER_IP/register` to create your admin account. Registration closes automatically after the first account is created.
2. Edit your configuration:
   ```bash
   nano ~/threatintel-platform/.env
   nano ~/threatintel-platform/config/keywords.yaml
   nano ~/threatintel-platform/config/seeds.txt
   ```
3. Restart to apply changes:
   ```bash
   cd ~/threatintel-platform && docker compose restart dashboard
   ```

### Updating

```bash
cd ~/threatintel-platform
git pull
docker compose build --no-cache
docker compose up -d
```

### Web Check (manual step)

Web Check runs as a separate service and is not started by default. See [docs/deployment.md](docs/deployment.md#web-check-integration) for setup steps.

---

## Configuration

All configuration lives in `.env`. **Never commit this file.**

### Minimum required variables

| Variable | Description |
|----------|-------------|
| `DASHBOARD_SECRET_KEY` | Flask session secret — must be a long random string; the app refuses to start without it |
| `POSTGRES_PASSWORD` | PostgreSQL password — auto-generated by deploy.sh |
| `DATABASE_URL` | PostgreSQL connection string — auto-set by deploy.sh |
| `TOR_CONTROL_PASSWORD` | Tor control port password — auto-generated by deploy.sh |

### Threat intelligence feeds

| Variable | Description |
|----------|-------------|
| `RANSOMWARE_LIVE_API_KEY` | ransomware.live PRO — free at my.ransomware.live; unlocks IOCs, negotiations, YARA rules, 3 000 calls/day |
| `THREATFOX_API_KEY` | ThreatFox (abuse.ch) — free at threatfox.abuse.ch |
| `WHITEINTEL_API_KEY` | WhiteIntel — free tier at whiteintel.io — credential exposure monitoring |
| `OTX_API_KEY` | AlienVault OTX — free at otx.alienvault.com |
| `ABUSEIPDB_API_KEY` | AbuseIPDB — free tier: 1 000 checks/day |
| `VIRUSTOTAL_API_KEY` | VirusTotal — free tier: 4 req/min |
| `DNSDUMPSTER_API_KEY` | DNSDumpster — for DNS investigation enrichment |

(Mailgun keys are retained in .env.example for backward compatibility but the daily digest feature is not implemented — see Roadmap.)

### Telegram

| Variable | Description |
|----------|-------------|
| `TELEGRAM_API_ID` | From my.telegram.org/apps |
| `TELEGRAM_API_HASH` | From my.telegram.org/apps |
| `TELEGRAM_PHONE` | Your phone number with country code — required for Channel Monitor |
| `TELEGRAM_CHANNELS` | Comma-separated channel usernames (no @) — used by background scraper |

(Quick Scan is a planned feature — see Roadmap.)

### OAuth (optional)

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth — callback: `/oauth/google/callback` |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth — callback: `/oauth/github/callback` |
| `MICROSOFT_CLIENT_ID` / `MICROSOFT_CLIENT_SECRET` / `MICROSOFT_TENANT_ID` | Microsoft OAuth |
| `APPLE_CLIENT_ID` / `APPLE_CLIENT_SECRET` | Apple Sign In |

See `.env.example` for all variables with descriptions and safe placeholder values.

---

## Test Suite

```bash
source .venv/bin/activate
pytest tests/ -v
```

Current count: **176 passed, 2 skipped**. Tests cover:

- Scanner keyword matching (hit detection, case insensitivity, context windows, add/remove)
- Crawler URL normalisation, domain extraction, link extraction, crawl filter logic
- HTTP client (safe\_fetch allowlist, IP blocklist, TLS enforcement, redirect re-validation, IPv4-mapped IPv6 blocking, SSRF guard)
- Storage models, session lifecycle, and Storage methods (unit + integration against SQLite)
- Proxy route wiring (integration, with safe\_fetch mocked)
- Tor connectivity (skipped unless `TOR_INTEGRATION=1`)

---

## Development Setup

```bash
git clone https://github.com/mwenda-cpu/kenyan-threatintelligence-platform
cd threatintel-platform
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,all]"
make setup          # copies .env.example → .env and example configs
```

Run the dashboard locally (requires a running PostgreSQL and Tor):

```bash
python -m darkweb_scanner.dashboard.app
```

Or via Docker Compose:

```bash
docker compose up -d
```

> Note: the Dockerfile CMD starts Flask's built-in server (`python -m darkweb_scanner.dashboard.app`). Migrating to gunicorn with a proper worker count is a planned follow-up.

---

## Project Structure

```
config/
  keywords.yaml          # keyword monitoring rules
  seeds.txt              # .onion seed URLs for the crawler
docs/                    # feature documentation
src/darkweb_scanner/
  crawler.py             # async Tor crawler (BFS, SOCKS5)
  scanner.py             # keyword matching engine
  storage.py             # SQLAlchemy models and storage layer
  quick_scan_sources.py  # source config and normalisation
  feeds.py               # OTX, CISA, abuse.ch, RSS feeds
  digest.py              # daily email digest + PDF
  dns_crawler.py         # DNS recon, brute-force, port scan, dir enum
  ip_lookup.py           # IP investigation (AbuseIPDB + VirusTotal)
  ransomware_live.py     # ransomware.live PRO API client
  ransomware_data.py     # local ransomware group data (merged with live API)
  threat_actors.py       # threat actor profile data
  telegram_scraper.py    # background Telegram channel scraper
  channel_monitor.py     # on-demand Telegram channel monitor
  paste_monitor.py       # rentry.co paste polling
  auth.py                # bcrypt, TOTP, OAuth helpers
  dashboard/
    app.py               # Flask application factory
    http_client.py       # safe_fetch — hardened outbound HTTP client
    auth_routes.py       # /login, /register, /totp/*, /oauth/*
    dashboard_routes.py  # all API and dashboard routes
    ransomware_live_routes.py  # /api/rwlive/* blueprint
    channel_monitor_routes.py  # Channel Monitor API + job runner
    quick_scan_routes.py       # /api/quick-scan/* blueprint
    storage_helper.py    # request-scoped Storage singleton
    templates/
      index.html         # single-page dashboard UI
docker/
  app/Dockerfile         # app image; non-root (appuser uid 1000)
  tor/Dockerfile         # Tor sidecar; non-root (debian-tor)
  nginx/                 # nginx with auto SSL entrypoint
deploy.sh                # zero-prerequisite deployment script
```

---

## Useful Commands

```bash
# Run from the install directory

make scan          # run a crawl (foreground)
make check-tor     # verify Tor connectivity
make stats         # show scan statistics
make hits          # show recent keyword hits
make logs          # tail all container logs
make stop          # stop all containers
```

---

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only).

You may use, modify, and distribute this software. If you run a modified version as a network service, you must make the source code available to users of that service.

See the [LICENSE](LICENSE) file for the full text.

---

## Contributing


Issues and feature requests: https://github.com/mwenda-cpu/kenyan-threatintelligence-platform/issues


## External API
See API.md for the read-only Threat Intelligence REST API (auth header, endpoints, curl examples).
Rate limiting: none by default.
All endpoints return JSON.
