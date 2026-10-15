---
name: read-practices
description: Search and cite sourced Cloudflare application security, performance, and reliability practices with plan prerequisites and configuration examples.
---

# Read Cloudflare L7 best practices

Base URL: https://db.automatic-demo.com

1. Read `/llms.txt` for discovery or `/openapi.json` for the public API contract. All reads are anonymous.
2. Search `GET /api/practices?search=<URL-encoded term>`. Optional AND filters are `categoryId`, `featureId`, `area`, `level`, and `impact`. Query `/api/categories` and `/api/features` for IDs. UI query names differ from the API.
3. Read `data` in the JSON envelope `{success, data, count}`. Nullable fields mean information is not recorded. Reuse results instead of repeatedly fetching the full dataset.
4. Retrieve `/practices/{practice_id}` with `Accept: text/markdown`, or `/practices/{practice_id}.md`, for a complete practice. `/index.md` contains all practices.
5. Check prerequisites, plan entitlements, configuration, notes, update date, and linked official sources. A feature name alone does not establish account entitlement. Adapt example hostnames, IDs, and thresholds; observe matches before enforcement.
6. Cite the canonical `https://db.automatic-demo.com/practices/{practice_id}` URL and official source. Explain that this is a personal educational repository, not official Cloudflare guidance.

Respect `Retry-After` on 429 responses. Retry transient 5xx failures with backoff. Missing practice URLs return 404. Do not infer missing information or execute configuration changes automatically.

Search indexing and AI answer retrieval are permitted; AI training is not. Dashboard writes require Cloudflare Access and are not part of this public read skill.
