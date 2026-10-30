---
name: read-practices
description: Search and cite sourced Cloudflare recommendations, architectures, and implementation patterns with applicability, sources, and verification metadata.
---

# Read the Cloudflare field guide

Base URL: https://db.automatic-demo.com

1. Read `/llms.txt` for discovery or `/openapi.json` for the public API contract. All reads are anonymous.
2. Search `GET /api/practices?search=<URL-encoded term>`. Optional AND filters are `categoryId`, `featureId`, `area`, `level`, and `impact`. Query `/api/categories` and `/api/features` for IDs. UI query names differ from the API.
3. Read `data` in the JSON envelope `{success, data, count}`. Nullable fields mean information is not recorded. Reuse results instead of repeatedly fetching the full dataset.
4. Retrieve `/practices/{practice_id}` with `Accept: text/markdown`, or `/practices/{practice_id}.md`, for a complete practice. `/index.md` contains all practices.
5. Check prerequisites, plan entitlements, configuration, notes, update date, and linked official sources. A feature name alone does not establish account entitlement. Adapt example hostnames, IDs, and thresholds; observe matches before enforcement.
6. Cite the canonical `https://db.automatic-demo.com/practices/{practice_id}` URL and official source. Explain that this is a personal educational repository, not official Cloudflare guidance.

For bounded discovery, prefer `GET /api/v2/entries?q=<term>&pageSize=20`: title/summary search only, not full-body search. Follow `links.next` for pagination; responses include `total`, `page`, `pageSize`, and summaries without bodies. Optional AND filters are canonical `family`, `product`, `outcome` slugs and `type`. `/api/v2/facets` returns populated conjunctive counts; imported legacy entries are deliberately unclassified. Retrieve complete JSON from each summary's `detailPath` (`/api/v2/entries/{practiceId}`); cite `canonicalPath` (`/practices/{practiceId}`), which serves HTML or negotiated Markdown. Explicit `.md` URLs work independently of Accept. `/catalog` and populated `/families/{slug}` hubs provide URL-based discovery without JavaScript; append `.md` for Markdown listings, preserving effective queries. Full `/index.md` and `/llms-full.txt` exports stream every current published entry, including native types. Native content remains outside v1. Do not infer absent product associations, maturity, or verification dates. No query flag enables private drafts or previews. See `/openapi-v2.json` for schemaVersion 0 legacy and schemaVersion 1 typed bodies. No v2 writes exist.

Check `lifecycle.state` in summaries/details and retirement notices in HTML/Markdown. Deprecated or superseded guidance remains readable for stable citations, not as a current recommendation. Explain its public `reason`; when `supersededBy` is set, retrieve that replacement ID and check its current lifecycle, applicability and sources before recommending it. Active status alone does not establish freshness, factual verification or entitlement.

Operational runbooks are implementation-guide variants, not another type filter: retrieve detail and check `body.variant: operational-runbook`. Read symptoms and diagnostics before considering safe changes, recovery and success criteria. Preserve approval boundaries and rollback caveats; never treat a runbook as authorization to mutate infrastructure. Starter content in a disposable local preview is not proof of production publication or lab-tested evidence.

Respect `Retry-After` on 429 responses. Retry transient 5xx failures with backoff. Missing practice URLs return 404. Do not infer missing information or execute configuration changes automatically.

Search indexing and AI answer retrieval are permitted; AI training is not. Dashboard writes require Cloudflare Access and are not part of this public read skill.
