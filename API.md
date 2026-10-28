# Threat Intelligence REST API

All endpoints are read-only and require the header `X-API-Key: <TI_API_KEY>`.

Base URL: `/api/v1`

## Authentication
```
X-API-Key: <value of TI_API_KEY env var>
```
Unauthenticated requests return `401 {"error":"Unauthorized"}`.

## Endpoints
- `GET /api/v1/health` -> `{"status":"ok","version":"1.0"}`
- `GET /api/v1/iocs?type=&value=&limit=50&offset=0` -> list of IOCs
- `GET /api/v1/iocs/<ioc_value>` -> IOC with related hits and sessions
- `GET /api/v1/sessions?limit=&offset=` -> crawler sessions
- `GET /api/v1/sessions/<id>/hits` -> hits for a session
- `GET /api/v1/threats?keyword=&limit=` -> ransomware/keyword hits
- `GET /api/v1/reports` -> list generated PDF report metadata
- `GET /api/v1/reports/<id>/download` -> download PDF
- `GET /api/v1/lookup/domain/<domain>` -> domain reputation aggregator
- `GET /api/v1/lookup/ip/<ip>` -> IP reputation aggregator

## Example curl
```
curl -H "X-API-Key: $TI_API_KEY" http://localhost:8080/api/v1/health
curl -H "X-API-Key: $TI_API_KEY" "http://localhost:8080/api/v1/iocs?type=ip&limit=10"
curl -H "X-API-Key: $TI_API_KEY" http://localhost:8080/api/v1/lookup/domain/example.com
```

## Rate limiting
None by default.

## Response schema
Collections return JSON arrays. Single resources return objects. Datetimes are ISO8601. Missing external API keys result in `"unavailable"` source fields.
