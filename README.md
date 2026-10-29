# Cloudflare L7 Best Practices Repository

A searchable repository of security, performance, and reliability best practices for Cloudflare application (Layer 7) services, built on Cloudflare Workers and D1.

## Features

- Instant search with highlighting, filters, sortable columns, expandable details, and canonical practice URLs (`/practices/<id>`; old `/#practice-<id>` links still work)
- Shareable views: search, filter, and sort state is kept in the URL
- Responsive: sticky toolbar and table header on desktop, sortable cards on phones, light/dark themes
- Shared expression/configuration copy controls, line wrapping, and accessible feedback on catalog details and canonical practice pages
- Server-rendered practice links remain available if the interactive API request fails
- Dashboard to add entries, protected by Cloudflare Access
- Crawlable, server-rendered content with canonical metadata, structured data, sitemap, and source/update information
- Agent-friendly Markdown negotiation, explicit Markdown URLs, public OpenAPI discovery, agent skill, and read-only WebMCP search in supporting browsers

## Architecture

| Layer           | Implementation                                                                                                                                                                                                                              |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Frontend        | Vanilla HTML/CSS/JS in [`public/`](public/); CSS, JS, images, and discovery files use free [Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/). The homepage is a server-rendered static template.            |
| API / documents | Typed gateway in [`src/index.ts`](src/index.ts); read filters/cache normalization in [`src/read-api.ts`](src/read-api.ts); Access, bounded JSON reading, validation, and durable creation in separate `src/` modules.                       |
| Read caching    | [Workers Cache](https://developers.cloudflare.com/workers/cache/) on `PublicReads`: hits skip that entrypoint's code and D1, but the uncached gateway still runs; writes/replays attempt a tag purge                                        |
| Database        | [D1](https://developers.cloudflare.com/d1/) with [migrations](migrations/); [`initial_data.sql`](initial_data.sql) is a production snapshot (`npm run db:seed:refresh`)                                                                     |
| Auth            | [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/) on `/dashboard`; the Worker also validates the Access JWT on writes                                                                                  |
| Observability   | Workers Logs, Traces, and [Issues](https://developers.cloudflare.com/workers/observability/issues/) (error monitoring); [Local Explorer](https://developers.cloudflare.com/workers/local-development/local-explorer/) during `wrangler dev` |

Workers Cache is enabled per entrypoint ([`wrangler.jsonc`](wrangler.jsonc)), not Worker-wide: enabling it on the default entrypoint would bill static asset requests, which are otherwise free ([pricing](https://developers.cloudflare.com/workers/cache/#pricing)).

The homepage, practice pages, Markdown exports, sitemap, agent index, and negotiated API docs invoke the gateway so responses can be rendered or negotiated. D1-derived reads use the primary database and share the `practices` purge tag across HTML, Markdown, JSON, and discovery. Accept is normalized before the cached entrypoint; `Vary: Accept` keeps representations separate. Documents drop UI queries; JSON APIs retain only canonical, effective filters. All other file assets remain asset-first.

Edge responses are fresh for one hour and eligible for stale-while-revalidate for another 24 hours. Writes await a purge attempt, but a failed purge does not undo the write. Purges do not clear browser caches, which have separate TTLs; immediate global read-after-write visibility is not guaranteed.

## Getting Started

```bash
npm ci
npx wrangler d1 create D1_DB_L7_BEST_PRACTICES --location weur   # once, if the database does not exist
./create_d1_schema.sh --local --seed                              # local schema + production snapshot
cp .dev.vars.example .dev.vars                                    # allow dashboard writes on localhost
npm run dev
```

For a fork, replace the Worker name, D1 identifiers, custom domain, and Access issuer/audience in `wrangler.jsonc`. Update canonical URLs in `src/content-rendering.ts` and public discovery files for the new hostname. Use a separate database and Access application for staging; never point local development at production via `remote: true`.

Test and deploy:

```bash
npm test -- --run
npm run typecheck
npm run content:check             # Python 3; offline seed + twice-applied active patches
npx wrangler types --check
npx wrangler deploy --dry-run
# Only with owner approval, after a production-copy rehearsal and private recovery bookmark:
./create_d1_schema.sh --remote   # apply pending migrations (idempotent)
npx wrangler d1 execute DB --remote --file=data/copyable-expressions.sql
npx wrangler d1 execute DB --remote --file=data/content-review-2026-10-29.sql
npm run deploy
npm run db:seed:refresh          # only after the remote data update
```

After changing bindings in `wrangler.jsonc`, run `npm run cf-typegen`.

[CI](.github/workflows/verify.yml) runs tests, strict type checking, catalog integrity/repeat-run checks, generated-type verification, and a deployment dry run without deployment credentials. It never applies remote migrations or deploys.

### Durable creation upgrade

**Deployed on 2026-10-29.** See the [rollout verification](docs/rollout-2026-10-29.md) for migration, production-copy rehearsal, live checks, and remaining manual validation.

Apply migration `0005_practice_creations.sql` **before deploying** the new write handler/dashboard. It adds a private `PracticeCreations` table without rebuilding catalog tables or changing existing IDs. Creation and its receipt use one transactional D1 batch; retries cannot commit a practice without its receipt. Keep receipts as long as their practices, and include them in private full backups, not public seed exports. Do not delete them as a routine cleanup.

Rehearse on an isolated production export before remote writes, following the [D1 best practices](https://developers.cloudflare.com/d1/best-practices/) and [import/export guide](https://developers.cloudflare.com/d1/best-practices/import-export-data/). Keep full exports and Time Travel bookmarks outside this public repository. Then, with owner approval, take a current bookmark, apply pending migrations, deploy code and dashboard together, and verify authenticated retry/conflict behavior and cache invalidation. `initial_data.sql` remains a production-only catalog snapshot; this migration does not require changing it.

### Copyable expressions upgrade

Migration `0004_copyable_expression.sql` adds the optional `expression` field. Apply it **before deploying** code that reads this field. The existing configuration field and practice IDs are preserved. The dashboard accepts expressions separately from actions, thresholds, and other guidance; public JSON, HTML, and Markdown expose the same distinction.

After migrations, apply `data/copyable-expressions.sql` to separate 51 already-recorded examples from their configuration guidance. The data file is re-runnable and leaves populated expression fields alone. Local seeding applies it automatically. To upgrade an existing local database:

```bash
npm run db:migrate:local
npx wrangler d1 execute DB --local --file=data/copyable-expressions.sql
```

For production, first rehearse the migration and data file twice on an isolated production export and take a Time Travel bookmark, as described in [AGENTS.md](AGENTS.md). Apply the migration and data file remotely before deploying, invalidate cached representations, then refresh `initial_data.sql` from production. This data separation is not a new review of product availability; all recorded prerequisites and caveats still apply.

The [2026-10-22 rollout verification](docs/frontend-rollout-2026-10-22.md) records the production migration, deployment, desktop/mobile checks, and refreshed-seed validation.

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

Dashboard writes require JSON of at most **64 KiB in bytes** and a random `Idempotency-Key` (16–128 letters, digits, hyphens, or underscores). Retry unchanged data with the same key: the API returns the original `201` and ID, or `409` if the completed key's normalized data differs. Keys are scoped to the verified Access identity (user subject or signed service-token identity) and retained durably. The dashboard keeps its key across retries/tab reloads, without storing form contents. See [the write contract](public/auth.md) for reset/storage limitations. Writes are same-origin only and responses are `no-store`.

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

The [2026-10-29 content review](data/content-review-2026-10-29.md) was applied to production: five practices corrected, 13 added, **119 total**, including two Reliability entries. `initial_data.sql` is the refreshed production catalog. Local seeding replays the review patch safely; existing local databases can apply it after migrations and `data/copyable-expressions.sql`. The [previous review](data/content-review-2026-10-15.md) remains a historical source record.

Run `npm run content:check` (Python 3) to validate the production seed and active patches, including repeat-run timestamps/sequences. This offline check does not replace rehearsal on an isolated current production export before remote application; see [AGENTS.md](AGENTS.md). After an approved remote update, invalidate cached reads and refresh the production seed. Example hostnames, thresholds, and token IDs must be adapted; feature labels are not proof of a particular account's entitlement. Record product/phase/action, prerequisites and maturity, limitations, observation/enforcement/rollback, official sources, and a separate fact-verification date in the editorial review.

## Disclaimer

This is a personal project for educational and informational purposes only. It is not an official Cloudflare product, and its content does not represent official Cloudflare guidance or the views of the author's employer.

The recorded best practices are provided "as is", without warranty of any kind. They may be incomplete, outdated, or unsuitable for your environment, plan, or compliance requirements. Always validate them against the [official Cloudflare documentation](https://developers.cloudflare.com/) and observe matches before enforcement. Action availability is product/phase-specific: request-phase custom/rate limiting _Log_ requires Enterprise; the response-WAF announcement describes separate Log/Block availability. API clients cannot solve interstitial challenges.

The author and contributors are not responsible or liable for any damage, outage, security incident, data loss, or other consequence arising from the use of, or reliance on, any information in this repository or on the website. You use it at your own risk.

Cloudflare and related marks are trademarks of Cloudflare, Inc.

```text
THIS SOFTWARE IS PROVIDED BY CLOUDFLARE "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CLOUDFLARE BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
