# Cloudflare L7 Best Practices Repository

A searchable repository of security, performance, and reliability best practices for Cloudflare application (Layer 7) services, built on Cloudflare Workers and D1.

## Features

- Instant search with highlighting, filters, sortable columns, expandable details, and canonical practice URLs (`/practices/<id>`; old `/#practice-<id>` links still work)
- Shareable views: search, filter, and sort state is kept in the URL
- Responsive: sticky toolbar and table header on desktop, cards on phones, light/dark themes
- Dashboard to add entries, protected by Cloudflare Access
- Crawlable, server-rendered content with canonical metadata, structured data, sitemap, and source/update information
- Agent-friendly Markdown negotiation, explicit Markdown URLs, public OpenAPI discovery, agent skill, and read-only WebMCP search in supporting browsers

## Architecture

| Layer           | Implementation                                                                                                                                                                                                                              |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Frontend        | Vanilla HTML/CSS/JS in [`public/`](public/); CSS, JS, images, and discovery files use free [Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/). The homepage is a server-rendered static template.            |
| API / documents | Uncached gateway in [`src/index.js`](src/index.js); public document rendering/negotiation in [`src/`](src/). Explicit Worker-first paths cover public documents and APIs.                                                                   |
| Read caching    | [Workers Cache](https://developers.cloudflare.com/workers/cache/) on the `PublicReads` entrypoint: cache hits skip Worker code and D1; writes purge by tag                                                                                  |
| Database        | [D1](https://developers.cloudflare.com/d1/) with [migrations](migrations/); [`initial_data.sql`](initial_data.sql) is a production snapshot (`npm run db:seed:refresh`)                                                                     |
| Auth            | [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/) on `/dashboard`; the Worker also validates the Access JWT on writes                                                                                  |
| Observability   | Workers Logs, Traces, and [Issues](https://developers.cloudflare.com/workers/observability/issues/) (error monitoring); [Local Explorer](https://developers.cloudflare.com/workers/local-development/local-explorer/) during `wrangler dev` |

Workers Cache is enabled per entrypoint ([`wrangler.jsonc`](wrangler.jsonc)), not Worker-wide: enabling it on the default entrypoint would bill static asset requests, which are otherwise free ([pricing](https://developers.cloudflare.com/workers/cache/#pricing)).

The homepage, practice pages, Markdown exports, sitemap, agent index, and negotiated API docs invoke the gateway so responses can be rendered or negotiated. D1-derived reads use the primary database and share the `practices` purge tag across HTML, Markdown, JSON, and discovery. Accept is normalized before the cached entrypoint; `Vary: Accept` keeps representations separate. UI query strings do not multiply identical cached documents. All other file assets remain asset-first.

## Getting Started

```bash
npm ci
npx wrangler d1 create D1_DB_L7_BEST_PRACTICES --location weur   # once, if the database does not exist
./create_d1_schema.sh --local --seed                              # local schema + production snapshot
cp .dev.vars.example .dev.vars                                    # allow dashboard writes on localhost
npm run dev
```

Test and deploy:

```bash
npm test
npm run typecheck
npx wrangler deploy --dry-run
./create_d1_schema.sh --remote   # apply pending migrations (idempotent)
npm run deploy
```

After changing bindings in `wrangler.jsonc`, run `npm run cf-typegen`.

## API

| Endpoint                        | Description                                                                                         |
| ------------------------------- | --------------------------------------------------------------------------------------------------- |
| `GET /api/practices`            | All practices. Optional filters: `search`, `categoryId`, `featureId`, `area`, `level`, `impact`     |
| `GET /api/categories`           | Categories                                                                                          |
| `GET /api/features`             | Cloudflare features                                                                                 |
| `GET /practices/{id}`           | Full practice HTML; send `Accept: text/markdown` for Markdown                                       |
| `GET /openapi.json`             | Public read-only API schema; [human-readable documentation](https://db.automatic-demo.com/api-docs) |
| `POST /dashboard/api/practices` | Create a practice (Access-protected, JSON body)                                                     |

Dynamic document routes and JSON API reads support GET, HEAD, and OPTIONS. Public read resources allow anonymous cross-origin access. A 429 response includes `Retry-After: 60`. The API schema documents filters and nullable fields; UI query names differ from API parameters.

## SEO, AEO, and agent access

Public HTML is indexable and readable without JavaScript. The homepage includes practice summaries and links; each `/practices/{id}` page includes full content, prerequisites, configuration, source links, a recorded update date, canonical/Open Graph metadata, and TechArticle/Breadcrumb structured data. The interactive table progressively enhances the homepage.

```bash
curl -H 'Accept: text/markdown' https://db.automatic-demo.com/
curl -H 'Accept: text/markdown' https://db.automatic-demo.com/practices/1
curl 'https://db.automatic-demo.com/api/practices?search=WAF&area=Security'
```

`/`, `/practices/{id}`, and `/api-docs` default to HTML, support Markdown negotiation, and send `Vary: Accept`. Explicit Markdown is available regardless of Accept:

| Resource                                     | Purpose                                                           |
| -------------------------------------------- | ----------------------------------------------------------------- |
| `/index.md`, `/llms-full.txt`                | Complete repository content as `text/markdown`                    |
| `/practices/{id}.md`                         | Full details of one practice as `text/markdown`                   |
| `/llms.txt`                                  | Live agent index with practice URLs and usage instructions        |
| `/sitemap.xml`                               | Live canonical HTML URLs and recorded practice modification dates |
| `/api-docs`, `/api-docs.md`, `/openapi.json` | API documentation and machine-readable contract                   |
| `/.well-known/api-catalog`                   | RFC 9727 API discovery (`application/linkset+json`)               |
| `/.well-known/ai-catalog.json`               | Draft ARD capability discovery pointing to real public resources  |
| `/.well-known/agent-skills/index.json`       | Discoverable read-practices skill with verified SHA-256 digest    |
| `/auth.md`                                   | Anonymous read access and Access-protected contribution guidance  |

Link response headers advertise canonical/Markdown URLs, sitemap, API catalog, schema, and documentation. Supporting browsers can discover the feature-detected read-only `search_cloudflare_practices` WebMCP tool.

[`robots.txt`](public/robots.txt) and [Content Signals](https://contentsignals.org/) allow **search indexing and AI answer retrieval**, while opting out of **AI training** (`search=yes, ai-input=yes, ai-train=no`). Known training crawlers and, by explicit owner policy, **PerplexityBot and Perplexity-User** are disallowed. Public readers are also subject to the deployment owner's security policy. The dashboard, 404 pages, and duplicate JSON API representations remain `noindex`; APIs are still available to permitted agents. `/dashboard` and the Cloudflare-managed [`/cdn-cgi/`](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/) paths are excluded from crawling.

The [implementation review](docs/agent-readiness.md) records the initial diagnostics, sources, and deployment checks. Robots directives are voluntary; production zone controls must match the published policy.

Local Lighthouse can flag a canonical mismatch because Wrangler rewrites Link response URLs to localhost while the HTML keeps production canonicals. Validate canonicals on the deployed hostname; local dev also does not emulate Workers Cache.

## Production settings (dashboard)

- [D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/) is not required by this architecture: Workers Cache serves reads close to users, and cache misses read from the primary to avoid caching stale replica results after a write.
- Follow the [deployment guidance](docs/agent-readiness.md#deployment-guidance) when configuring a fork or changing public access. Inspect the target account and zone configuration and obtain owner confirmation before changes.
- Protect dashboard routes with Cloudflare Access and configure the Worker's JWT validation. Keep public read endpoints anonymous.
- Scope any WAF or bot exceptions to the intended hostname, public read methods, and affected paths. Preserve existing restrictions, exclude blocked identities from exceptions, and validate Bot Management detection fields against current evidence. Dry-run changes before applying them and verify actual traffic behavior afterward.
- Align edge crawler controls and the merged robots response with the published search/retrieval/training policy. Review mixed-use crawlers individually rather than treating every AI crawler as training-only. Check both response headers and page metadata for unintended public `noindex` directives.
- Configure HTTPS and verify canonical URLs on the deployed hostname. Native Markdown negotiation does not require an edge HTML-to-Markdown converter. Crawler Hints is an optional discovery improvement; review its scope before enabling it.
- After deployment, verify HTML and Markdown cache variants (`Cf-Cache-Status`), write-triggered purges, public reads, dashboard protection, and the published crawler policy. Local dev does not emulate Workers Cache. Rerun the [readiness scan](https://isitagentready.com/db.automatic-demo.com) and submit `/sitemap.xml` to search consoles.

The [2026-10-15 release verification](docs/agent-readiness.md#verification-and-release) confirmed independent HTML/Markdown cache hits, the published merged robots policy, and Access-protected dashboard routes.

## Contributing

Pull requests with new best practices or improvements are welcome. Content updates are re-runnable SQL files in [`data/`](data/). Allowed users can also add entries through the dashboard.

The [2026-10-15 content review](data/content-review-2026-10-15.md) records sources, corrections, and production-copy verification. Rehearse a new data file twice on an isolated production export before remote application; see [AGENTS.md](AGENTS.md). After applying it remotely, invalidate cached reads and refresh the production seed. Example hostnames, thresholds, and token IDs must be adapted; feature labels are not proof of a particular account's entitlement.

## Disclaimer

This is a personal project for educational and informational purposes only. It is not an official Cloudflare product, and its content does not represent official Cloudflare guidance or the views of the author's employer.

The recorded best practices are provided "as is", without warranty of any kind. They may be incomplete, outdated, or unsuitable for your environment, plan, or compliance requirements. Always validate them against the [official Cloudflare documentation](https://developers.cloudflare.com/) and observe matches before enforcement (_Log_ for custom/rate limiting rules requires Enterprise; API clients cannot solve interstitial challenges).

The author and contributors are not responsible or liable for any damage, outage, security incident, data loss, or other consequence arising from the use of, or reliance on, any information in this repository or on the website. You use it at your own risk.

Cloudflare and related marks are trademarks of Cloudflare, Inc.
