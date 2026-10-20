# Kenya Deployment Guide — Threat Intelligence Platform (Kenya focus)

Target audience: Kenya government e-services teams, financial-sector SOCs
(CBK-supervised banks, M-Pesa/SACCO operators), and KE-CIRT/CC partners.

## 1. Overview

This deployment tunes the platform for Kenya:

- Ransomware/live feeds scoped to Kenya + East Africa (`KE`, `TZ`, `UG`,
  `RW`, `BI`, `ET`, `SO`, `DJ`, `ER`, `SS`) via `SEA_ISO2` / `KE_ISO2`.
- Kenya Context tab backed by three Kenyan sources:
  KE-CIRT/CC quarterly advisories, CA Kenya alerts, and CBK fraud stats.
- Keyword correlation matches global intel against Kenyan context so
  analysts see what matters for government e-services and finance first.

## 2. Prerequisites

- Docker Desktop (Windows/WSL2, macOS) or Docker Engine on Linux
- 4 GB RAM minimum (8 GB recommended), 20 GB free disk
- API keys (see `.env.example`): `RANSOMWARE_LIVE_API_KEY`, ThreatFox,
  AbuseIPDB, VirusTotal, OTX. The platform degrades gracefully when a
  key is missing.

## 3. One-command deploy

Linux:

```bash
git clone <repo-url> ~/threatintel-platform
cd ~/threatintel-platform
cp .env.example .env   # then edit .env with your keys
docker compose up -d --build
docker compose logs dashboard --tail 50
```

Windows / WSL2 (PowerShell):

```powershell
git clone <repo-url> C:\Users\<you>\threatintel-platform
cd C:\Users\<you>\threatintel-platform
Copy-Item .env.example .env   # then edit .env with your keys
docker compose up -d --build
docker compose logs dashboard --tail 50
```

Open the dashboard at `https://localhost/dashboard` (via nginx) or
`http://localhost:8080/` (dashboard directly, dev only).

## 4. Configuration checklist

- API keys: set every `*_API_KEY` in `.env`; restart the dashboard
  after any change (`docker compose restart dashboard`).
- Keyword tuning for Kenya: edit `config/keywords.yaml` — keep
  eCitizen, KRA, M-Pesa, bank/SACCO names, and Swahili fraud terms.
- Seeds list: curate `.onion` and clearnet seeds in `config/seeds.txt`
  (Kenya-relevant leak sites, paste sources, Telegram channels).
- KE ingestion schedule: create `./data/ke_reports/` and drop files
  with the `ke_cirt_*`, `ca_*`, `cbk_*` prefixes (see §5), or upload them
  from the dashboard (see §5.1).
- Write access to `./data/ke_reports/`: the dashboard container runs as
  uid 1000 (`appuser`) and `./data` is bind-mounted into it, so the host
  directory must be writable by that uid. On Linux run
  `sudo chown -R 1000:1000 ./data` after cloning. The dashboard logs
  `KE reports dir ... is not writable` at startup when it is not.

- Keyword list: keywords live in the `keywords` table in the database.
  `config/keywords.yaml` (and the legacy `data/keywords.yaml`) are only
  **seeds** — they are imported once when the table is empty. The crawler,
  the dashboard *Manage Keywords* panel and the API all read and write the
  table, so edits made in the dashboard are picked up by the next crawl.

## 5. Operational runbook

Daily:

- Check the IOC feed and quick-scan queue; confirm Tor is healthy
  (`docker compose ps`, dashboard System Status card).
- Review crawl hits and paste-monitor hits for Kenyan entities.
- Triage new ransomware victims with KE/TZ/UG/RW/ET/SO country codes.

Weekly:

- Refresh `.onion` seeds from deepdarkCTI / trusted feeds.
- Review CA advisories (`/api/ke-context/ca-advisories`) and update
  keywords for newly reported threat types.

Quarterly:

1. Download the new reports:
   - KE-CIRT/CC quarterly report — https://ke-cirt.go.ke
   - CA advisories — https://repository.ca.go.ke
   - CBK Financial Sector Stability report — https://www.centralbank.go.ke
  2. Save them into `./data/ke_reports/` with the right prefix.
  3. Ingest:
   ```bash
   docker compose exec dashboard python -m scripts.load_ke_reports --dry-run
   docker compose exec dashboard python -m scripts.load_ke_reports

### 5.1 Uploading reports from the dashboard

New KE-CIRT/CC, CA and CBK PDFs can be added without touching the host:
the **Kenya Context** tab has an *Upload KE Report* card (admin accounts
only).

1. Pick the source (CA advisory / KE-CIRT quarterly / CBK statistics).
2. Choose the PDF and press **Upload Report**.
3. The file is stored in `./data/ke_reports/` with the source prefix
   (`ca_`, `ke_cirt_`, `cbk_`), parsed immediately by
   `scripts/load_ke_reports.py`, and the tables refresh.

Every stored report gets a `file_url` (e.g.
`/api/reports/download/ca_advisory.pdf`) in the `/api/ke-context/*`
responses, and the report titles in the dashboard link to the PDF itself.
Uploads are limited to PDFs (30 MB by default, `KE_REPORT_MAX_BYTES`),
filenames are sanitised, and the download route refuses any path outside
`./data/ke_reports/`.

To ingest a file that is already on the host, the CLI still works:
```bash
docker compose exec dashboard python -m scripts.load_ke_reports --dry-run
docker compose exec dashboard python -m scripts.load_ke_reports
```

### 5.2 Purging and sanitising keyword hits

The scanner stores a **short, cleaned snippet** (max 250 characters) around
each keyword — never the page body. Page chrome is stripped at crawl time:
leak-site group menus ("v3 Open Bl4ckt0r v3 Open CL0P"), onion addresses,
crypto wallet dumps, cookie banners and legal pages. A keyword that only
appears in that navigation noise is not stored at all.

To purge historical junk (e.g. rows created before the cleaner existed):

```bash
# report only
docker compose exec dashboard python -m scripts.clean_keyword_hits --dry-run
# write the changes
docker compose exec dashboard python -m scripts.clean_keyword_hits --apply
```

The script deletes hits with the junk keywords `category`/`severity` (and
empty keywords), re-cleans the remaining snippets, truncates anything longer
than 500 characters and drops hits whose snippet contains nothing readable.

## 7. Data handling and legal notes

- License: AGPL-3.0 (see `LEGAL.md`). Derivative deployments must
  preserve the licence notice.
- No PII is collected beyond what operators configure (keywords,
  seeds, subscriber emails for the digest). Minimise personal data
  in keywords and purge crawl artefacts per your retention policy.
- Retention suggestion: raw crawl pages 90 days, keyword hits 1 year,
  KE reports indefinitely (they are small and versioned by period).
- Access control: keep `DASHBOARD_SECRET_KEY` strong, enable 2FA for
  admin accounts, and serve only over TLS (see `scripts/configure-ssl.sh`).

## 8. Evaluation methodology (proposal objective iv)

Goal: prove that Kenyan context improves detection and triage versus
a global-only baseline.

1. Build 3–5 synthetic scenarios from historical KE-CIRT/CC topics,
   e.g. "mobile banking trojan wave", "eCitizen DDoS week",
   "SACCO phishing kit reuse".
2. For each scenario, assemble 10–20 indicators (domains, hashes,
   Telegram phrases) and run Quick Scan twice:
   - A: Kenya-context enabled (keywords + correlate endpoint live)
   - B: Kenya-context disabled (baseline keyword set only)
3. Measure per scenario:
   - detection rate (hits / indicators),
   - mean time to correlate (scan start → correlate call returning
     ≥1 KE match),
   - false-positive ratio (analyst-marked benign hits / total hits).
4. Report A-vs-B deltas in the quarterly review; keep the raw scan
   exports under `./data/eval/` for auditability.

Known limitation: `correlate_keyword` is substring-based, so tune
keyword granularity and threat-type labels once real KE-CIRT data is
loaded; expect 1–2 iterations before the false-positive ratio settles.

   ```
4. Open the Kenya Context tab and confirm the new period appears.

## 6. Recommendations for Kenyan institutions

- KE-CIRT/CC: adopt this deployment as a supplementary feed —
  subscribe to the daily digest and cross-check advisories against
  the correlated keyword view.
- CBK BS-SOC / bank SOCs: enable keyword-hit alerts for bank names,
  M-Pesa rails, card processors and SACCOs; review CBK fraud-trend
  deltas each quarter before board reporting.
- Government MDAs (eCitizen, KRA, Huduma): run OSINT + paste-monitor
  sweeps on service domains weekly; treat credential-leak hits as P1.
