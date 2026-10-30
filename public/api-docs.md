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

These v1 responses are `{"success": true, "data": [...], "count": 123}`. Count is the number of returned records. v1 has no pagination. Nullable fields indicate missing information, not a default recommendation or plan entitlement.

`expression` is an optional, explicitly authored Rules expression. `expressions_configuration_details` retains the full configuration guidance, including actions, thresholds, commands, or counting expressions. Never treat that guidance as a paste-ready match expression. Adapt examples and check prerequisites before use.

`/api/practices` filters combine with AND:

- `search`: literal substring in title, description, expression, configuration, prerequisites, or notes. NULs are removed, input is trimmed and truncated to 200 UTF-16 code units. ASCII case-insensitive; non-ASCII case is exact. Percent, underscore and backslash are literal, not wildcard characters.
- `categoryId`, `featureId`: positive integer IDs from taxonomy endpoints.
- `area`: Security, Performance, Reliability, General.
- `level`: Mandatory, Recommended, Optional, Situational.
- `impact`: High, Medium, Low.

Invalid filter values are ignored. Unknown valid IDs return no records. The interactive table's `q`, `domain`, `category`, `feature`, and sort parameters are UI state, not API parameter names.

```bash
curl 'https://db.automatic-demo.com/api/practices?search=WAF&area=Security'
curl -H 'Accept: text/markdown' https://db.automatic-demo.com/
```

## Versioned catalog reads

- `GET /api/v2/entries`: published summaries only (no bodies/sources), with `count`, `total`, `page`, `pageSize`, `pages`, effective `query`, and relative `links.self/next/previous`.
- `GET /api/v2/entries/{id}`: complete published detail in `{success, data}`. Missing/unpublished entries return 404. No query parameter enables drafts or previews.
- `GET /api/v2/facets`: populated `types`, `families`, `products`, and `outcomes` in `{success, data}`. Counts apply all effective filters together, not self-excluding facets; draft-only taxonomy is absent.

List/facet filters combine with AND: `q` (literal substring in title/summary only, ASCII case-insensitive, trimmed to 200 Unicode code points), canonical `family`, `product`, `outcome` slugs, and `type` (`legacy-practice`, `recommendation`, `rule-policy`, `reference-architecture`, `implementation-guide`). SQL wildcard/operator syntax has no special meaning in `q`. This is not full-body or relevance-ranked search.

Operational runbooks use `type: implementation-guide` and `body.variant: operational-runbook`, with explicit task, symptoms, read-only diagnostics, approved safe changes, recovery, success criteria and rollback. Retrieve the detail before interpreting its variant; summary search/facets intentionally do not read bodies. No `type=operational-runbook` filter is implemented. A runbook's change instructions never grant permission to mutate an account.

Listings accept `sort=title` (default) or `sort=newest` (recorded modification date descending), always with numeric ID ascending as tie-breaker. `page` defaults to 1 (maximum 10000); `pageSize` defaults to 20 (maximum 50). Positive values above these bounds are clamped; malformed/zero values use defaults. Empty/out-of-range pages return empty data with the true total. `pages` is the mathematical total; `next` stops at page 10000, so refine filters for larger result sets. Offset pages can shift if content changes between requests. Facets ignore sort/pagination.

Unknown/default parameters disappear from the cache key. Malformed filters are ignored, unknown valid slugs return no matches, and the first duplicate parameter wins. Legacy imports use `schemaVersion: 0`, `type: legacy-practice`, `revisionId: null`, an unchanged v1 body, and unknown taxonomy/evidence rather than invented facts. Typed bodies use `schemaVersion: 1` and a published revision. Native entries are not automatically eligible for v1. Use `canonicalPath` for the HTML citation URL and `detailPath` for JSON retrieval. Each published entry supports Markdown negotiation and an explicit `.md` alias. Full Markdown exports stream all current published entries; v1 remains legacy-only.

Summaries and details include `lifecycle: {state, reason, supersededBy}`. State is `active`, `deprecated`, or `superseded`. Retired guidance remains readable at its stable URL with a public reason; `supersededBy` is the replacement's practice ID, or null when there is no replacement. Retrieve the replacement and check its current status, sources and applicability before use. Do not present retired examples as current recommendations. Active status alone does not establish freshness, factual verification or account entitlement.

`/catalog` provides HTML search with the same v2 filters, sorting and pagination, without JavaScript. Populated `/families/{slug}` hubs lock the family filter. Both listings retain effective query state, remove tracking/default parameters before caching, negotiate Markdown, and have explicit `.md` aliases (`/catalog.md`, `/families/{slug}.md`). Empty or unknown family hubs return 404; a valid hub with no matching filtered results returns an empty result page. Existing `/` and entry URLs still drop UI-only query state. Old `/#practice-{id}` bookmarks remain links to canonical entries; the homepage no longer downloads the full-body catalog.

```bash
curl 'https://db.automatic-demo.com/api/v2/entries?q=WAF&pageSize=10'
curl 'https://db.automatic-demo.com/api/v2/entries/18'
```

See [the v2 schema](/openapi-v2.json) for body variants and nullable metadata. These interfaces are additive; existing clients need not migrate. There are no v2 write endpoints.

## Operational behavior

Public reads support GET, HEAD, and OPTIONS and allow cross-origin access. Cache results: practice documents and API responses have a 60-second client TTL, taxonomy responses 300 seconds. Edge cache fills use the primary database and dashboard writes purge practice representations together.

JSON API failures use `{"success": false, "error": "..."}` and a non-2xx HTTP status. Respect `429` and `Retry-After: 60`; retry transient 5xx errors with backoff. Missing practice pages are 404, not successful empty documents.

## Authentication and discovery

Writes exist only under the Cloudflare Access-protected dashboard. See [auth.md](/auth.md). Public integrations should use read endpoints.

The typed editorial workflow is implemented locally, not deployed. Its [protected schema](/openapi-editorial.json) documents private draft/review/publication routes; Access login additionally requires owner-provisioned editorial roles. These routes are not public agent tools and cannot be enabled with a public query flag.

- [OpenAPI](/openapi.json)
- [API catalog](/.well-known/api-catalog)
- [Agent skills](/.well-known/agent-skills/index.json)
- [Capability manifest](/.well-known/ai-catalog.json)

Search indexing and AI answer retrieval are permitted; AI training is not. This is a personal educational project, not official Cloudflare guidance. Validate sources, freshness, prerequisites, and your plan before applying examples.
