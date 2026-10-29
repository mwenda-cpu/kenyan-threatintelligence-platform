# Fintech Threat Watchlist — Integration Guide

## Overview

The Fintech Threat Watchlist module turns the platform into a lightweight
Fintech TIP (Threat Intelligence Platform) for financial institutions.
Instead of ingesting synthetic transactions, it exposes a **lookup API** that
SOC teams can use to query suspicious IPs and phone numbers against a curated
watchlist of Dark Web and KE-CIRT threat indicators.

Use cases:
- A bank SOC analyst checks whether a source IP seen in transaction logs is a
  known SIM-swap threat before releasing funds.
- A fraud team verifies whether a customer phone number appears on the
  Dark Web watchlist for agent fraud or reversal fraud.
- Threat intel from the platform's Dark Web crawler can be promoted into the
  watchlist, creating a feedback loop between OSINT collection and fintech
  fraud prevention.

## Watchlist Schema

Table: `fintech_watchlist`

| Column | Type | Description |
|---|---|---|
| `id` | Integer PK | Auto-incrementing row ID |
| `identifier` | String(255) | IP address, phone number, or account identifier |
| `identifier_type` | String(20) | `"ip"` \| `"phone"` \| `"account"` |
| `threat_type` | String(100) | e.g. `"SIM-swap"`, `"B2C-reversal-fraud"`, `"agent-fraud"` |
| `source` | String(100) | `"darkweb"` \| `"KE-CIRT"` \| `"manual"` |
| `confidence` | Integer | 0-100 confidence score (default 70) |
| `created_at` | DateTime | When the entry was added |

Populating from Dark Web crawler hits: any crawled hit whose indicator is an
IP or phone number can be promoted into this table with `identifier_type` set
to `"ip"` or `"phone"` and `threat_type` set to the observed threat (e.g.
`"SIM-swap"`). The crawler already extracts IOCs via the `ThreatIOC` model;
those can be re-keyed into `fintech_watchlist` as needed.

## API Endpoints

All endpoints require an `X-API-Key` header matching `TI_API_KEY`.

### POST /api/v1/fintech/watchlist — Add a watchlist entry

```bash
curl -X POST http://localhost:8080/api/v1/fintech/watchlist \
  -H "X-API-Key: $TI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "192.0.2.10",
    "identifier_type": "ip",
    "threat_type": "SIM-swap",
    "source": "darkweb",
    "confidence": 90
  }'
```

### GET /api/v1/fintech/watchlist — List all watchlist entries

```bash
curl -H "X-API-Key: $TI_API_KEY" \
  "http://localhost:8080/api/v1/fintech/watchlist?limit=50"
```

### GET /api/v1/fintech/lookup — Look up an IP or phone on the watchlist

```bash
# Look up by IP
curl -H "X-API-Key: $TI_API_KEY" \
  "http://localhost:8080/api/v1/fintech/lookup?ip=192.0.2.10"

# Look up by phone
curl -H "X-API-Key: $TI_API_KEY" \
  "http://localhost:8080/api/v1/fintech/lookup?phone=%2B254712345678"
```

A SOC analyst investigating a suspicious transaction would run the lookup
against the source IP or sender phone. A non-empty result means the identifier
is on the watchlist and the transaction should be treated as high risk.

## Why Real M-Pesa / CBK Data Is Out of Scope

Real M-Pesa (Safaricom Daraja API) and CBK (Bank of Kenya BS-SOC) transaction
feeds require institutional API access, contractual agreements, and regulatory
compliance (data protection, financial secrecy laws). The platform intentionally
does not ingest real customer transaction data.

The platform **is ready** for institutional integration:
- The `fintech_watchlist` table accepts IP / phone / account identifiers from
  any source, including a future Daraja sandbox webhook or CBK BS-SOC feed.
- The lookup endpoint is designed to sit behind a bank's internal SOC
  workflow: feed in transaction metadata, get back a watchlist match or a
  clean result.

## UI

The dashboard exposes a **"Fintech Threat Watchlist"** tab where SOC staff can
enter an IP or phone number and see matching watchlist entries, including the
threat type, source, and confidence score.
