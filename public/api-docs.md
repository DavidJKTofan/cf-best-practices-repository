# Cloudflare L7 Best Practices — read API

Canonical documentation: https://db.automatic-demo.com/api-docs

Public reads are anonymous: no API key, registration, cookies, or JavaScript needed.

## Content formats

- `/` and `/practices/{id}` return HTML by default and Markdown for `Accept: text/markdown` (with `Vary: Accept`). Explicit `q=0` excludes Markdown; HTML wins when its quality is higher.
- `/index.md` and `/llms-full.txt` return all practice details as `text/markdown`.
- `/practices/{id}.md` returns a single practice as `text/markdown`.
- `/llms.txt` is the discovery index. Cite canonical `/practices/{id}` URLs and their official sources.
- `/sitemap.xml` lists canonical HTML URLs only.

## JSON endpoints

- `GET /api/practices`: all records, including prerequisites, configuration, sources, and update dates.
- `GET /api/categories`: category IDs and names.
- `GET /api/features`: feature IDs, names, and documentation URLs.

The response is `{"success": true, "data": [...], "count": 123}`. Count is the number of returned records. There is no pagination. Nullable fields indicate missing information, not a default recommendation or plan entitlement.

`/api/practices` filters combine with AND:

- `search`: literal substring in title, description, configuration, prerequisites, or notes; trimmed to 200 characters. SQL wildcard characters are treated literally.
- `categoryId`, `featureId`: positive integer IDs from taxonomy endpoints.
- `area`: Security, Performance, Reliability, General.
- `level`: Mandatory, Recommended, Optional, Situational.
- `impact`: High, Medium, Low.

Invalid filter values are ignored. Unknown valid IDs return no records. The interactive table's `q`, `domain`, `category`, `feature`, and sort parameters are UI state, not API parameter names.

```bash
curl 'https://db.automatic-demo.com/api/practices?search=WAF&area=Security'
curl -H 'Accept: text/markdown' https://db.automatic-demo.com/
```

## Operational behavior

Public reads support GET, HEAD, and OPTIONS and allow cross-origin access. Cache results: practice documents and API responses have a 60-second client TTL, taxonomy responses 300 seconds. Edge cache fills use the primary database and dashboard writes purge practice representations together.

JSON API failures use `{"success": false, "error": "..."}` and a non-2xx HTTP status. Respect `429` and `Retry-After: 60`; retry transient 5xx errors with backoff. Missing practice pages are 404, not successful empty documents.

## Authentication and discovery

Writes exist only under the Cloudflare Access-protected dashboard. See [auth.md](/auth.md). Public integrations should use read endpoints.

- [OpenAPI](/openapi.json)
- [API catalog](/.well-known/api-catalog)
- [Agent skills](/.well-known/agent-skills/index.json)
- [Capability manifest](/.well-known/ai-catalog.json)

Search indexing and AI answer retrieval are permitted; AI training is not. This is a personal educational project, not official Cloudflare guidance. Validate sources, freshness, prerequisites, and your plan before applying examples.
