# Cloudflare Field Guide

A sourced repository of Cloudflare recommendations, architectures, and implementation patterns, built on Cloudflare Workers and D1. Existing Layer 7 practice IDs and APIs are preserved.

**Local development checkpoint:** Phases 1–5 are implemented locally, not deployed. Phase 6 adds offline rehearsal, isolated staging-build checks and read-only release probes; an approved current private copy now passes offline/local D1/workerd rehearsal, while independent-review/exact-artifact/staging/live gates remain open. The Astro frontend, role-protected editorial workflow, and four curated Cloudflare One/Developer starters are verified with disposable fixtures. All 119 legacy records have an individual classification audit, not an automatic conversion. No native starter/pilot or role grant has been added to production or its seed. See the [roadmap](docs/cloudflare-platform-roadmap.md), [Phase 5 evidence/release limits](docs/phase5/curated-expansion.md) and [Phase 6 release runbook](docs/phase6/rehearsal-and-rollout.md).

## Features

- Server-rendered `/catalog` search, conjunctive filters, sorting, and pagination (20 summaries by default, maximum 50), using ordinary GET forms with progressive debounced search/immediate filters
- Populated family/outcome journeys, shareable effective query state, and canonical practice URLs (`/practices/<id>`; old `/#practice-<id>` bookmarks remain usable)
- Compact, minimal reference layout with system fonts, light/dark themes, keyboard focus, and complete reading/discovery without JavaScript
- Typed rule, architecture, implementation-guide and operational-runbook variant HTML/Markdown, with separate expression/action, text topology, file-oriented examples, recovery/rollback, sources, and freshness
- Shared expression/configuration copy controls, line wrapping, and accessible success/failure feedback
- Dashboard to add entries, protected by Cloudflare Access
- Typed editorial workbench with private drafts/previews, independent review, version conflicts, durable retry receipts and transactional publication
- Crawlable, server-rendered content with canonical metadata, structured data, sitemap, and source/update information
- Agent-friendly Markdown negotiation, explicit Markdown URLs, public OpenAPI discovery, agent skill, and read-only WebMCP search in supporting browsers

### Frontend design

The local Astro frontend follows the earlier UI's neutral palette, compact typography, subtle borders and simple result rows. It uses the system font stacks below, with no downloaded fonts:

```css
--font: system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
--mono: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;
```

Layouts adapt from mobile/tablet to desktop and 4K, with bounded listing/reading widths rather than monitor-wide prose. Extra filters and small-screen contents are collapsible. Empty configuration, notes, related-content, family/outcome and unused filter sections are omitted from server HTML, including their headings and contents links; selected zero-result filters stay available to clear. Sources, caveats, canonical links and honest freshness metadata are preserved. See the [local UI verification](docs/phase6/frontend-simplification.md); this redesign is **not deployed**.

Keep this README and [AGENTS.md](AGENTS.md) up to date when changing setup, behavior or design rules.

Catalog/family text search applies after 350 ms; dropdowns apply immediately. URLs, Back/Forward, focus and native no-JavaScript Search remain usable; failed live updates fall back to ordinary navigation. Pagination bounds response size, not substring-search/count/deep-offset cost. See the [scalability and production-readiness review](docs/phase6/scalability-and-production-readiness.md): a current private-copy migration/runtime rehearsal passes locally, but independent-review/staging/live gates remain open and production still lacks `/catalog` and v2.

## Architecture

| Layer           | Implementation                                                                                                                                                                                                                                                                                                                                      |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Frontend        | Astro SSR pages, shared components/layout and CSS under [`src/`](src/); small vanilla enhancements and dashboard in [`public/`](public/). Built CSS/JS/images/discovery stay asset-first with free [Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/). No hydrated UI framework or full-body catalog download.       |
| API / documents | [`src/astro-worker.ts`](src/astro-worker.ts) exports the existing gateway and Astro-aware cached reads; [`src/index.ts`](src/index.ts) remains the framework-independent regression entrypoint. Thin Hono groups in [`src/api/`](src/api/), catalog/taxonomy queries in [`src/modules/`](src/modules/), policy in [`src/platform/`](src/platform/). |
| Read caching    | [Workers Cache](https://developers.cloudflare.com/workers/cache/) on `PublicReads`: hits skip that entrypoint's code and D1, but the uncached gateway still runs; writes/replays attempt a tag purge                                                                                                                                                |
| Database        | [D1](https://developers.cloudflare.com/d1/) with [migrations](migrations/); [`initial_data.sql`](initial_data.sql) is a sanitized public production snapshot (never a full backup)                                                                                                                                                                  |
| Auth            | [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/) on `/dashboard`; the Worker also validates the Access JWT on writes                                                                                                                                                                                          |
| Observability   | Workers Logs, Traces, and [Issues](https://developers.cloudflare.com/workers/observability/issues/) (error monitoring); [Local Explorer](https://developers.cloudflare.com/workers/local-development/local-explorer/) during `wrangler dev`                                                                                                         |

Workers Cache is enabled per entrypoint ([`wrangler.jsonc`](wrangler.jsonc)), not Worker-wide: enabling it on the default entrypoint would bill static asset requests, which are otherwise free ([pricing](https://developers.cloudflare.com/workers/cache/#pricing)).

See [module ownership](docs/phase1/module-boundaries.md), the [Phase 2 model/read API](docs/phase2/model-and-read-api.md), [Phase 3 presentation](docs/phase3/frontend-and-pilots.md), [Phase 4 editorial contracts](docs/phase4/editorial-workflow.md), and [Phase 5 curated expansion](docs/phase5/curated-expansion.md). Sessions and incidental image/KV bindings are disabled. Builds are credential-free and do not read D1. Live native publication and role provisioning remain separately gated.

The homepage, catalog/family listings, practice pages, Markdown exports, sitemap, agent index, and negotiated API docs invoke the gateway. D1-derived reads start with `first-primary` and share the `practices` purge tag across HTML, Markdown, JSON, and discovery. Accept is normalized before the cached entrypoint; `Vary: Accept` separates representations. Existing documents drop UI queries; new catalog/family listings retain effective search/filter/sort/page state. Other file assets remain asset-first. Adapter finalization restores the established headers without buffering HTML; errors and cookies are never shared-cached.

Edge responses are fresh for one hour and eligible for stale-while-revalidate for another 24 hours. Writes await a purge attempt, but a failed purge does not undo the write. Purges do not clear browser caches, which have separate TTLs; immediate global read-after-write visibility is not guaranteed.

## Getting Started

Use **Node 22.23.4 or newer** (CI uses 22.23.4). Astro, its adapter/checker, and TypeScript are pinned to the tested compatible toolchain.

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
npm run release:check             # synthetic-only rehearsal/config/probe tooling checks
npx wrangler types --check
npm run frontend:check
npm run build
npm run frontend:test             # built Worker, public artifacts, and displayed D1 example
npm run deploy:check              # generated dist/server/wrangler.json; never deploy raw Astro source
# Only with owner approval, after a production-copy rehearsal and private recovery bookmark:
./create_d1_schema.sh --remote   # apply pending migrations (idempotent)
npx wrangler d1 execute DB --remote --file=data/copyable-expressions.sql
npx wrangler d1 execute DB --remote --file=data/content-review-2026-10-29.sql
npx wrangler d1 execute DB --remote --file=data/catalog-taxonomy.sql
npx wrangler d1 execute DB --remote --file=data/phase5-products.sql  # labels only, no native publication
npm run deploy
# Only after an approved remote update and verification; full backups stay outside the repository:
npx wrangler d1 export DB --remote --output=/path/outside/repository/full.sql
npm run db:seed:refresh -- /path/outside/repository/full.sql
```

After changing bindings in `wrangler.jsonc`, run `npm run cf-typegen`. `npm run deploy` builds first and deploys the generated configuration; it still requires explicit approval and the release gates above.

To inspect all three pilots without touching your normal local database or any remote resource:

```bash
npm run build
npm run preview:pilots                  # fresh in-memory harness, with the public seed and test-only pilots
npm run preview:pilots -- --no-scripts   # also prints a local CSP-blocked browser rehearsal URL
```

Preview ports are printed at startup. Stop with Ctrl-C; fixture data is not retained. These are authored test fixtures, not a production publication script.

For the two Phase 5 implementation/recovery pairs instead of the pilots, run `npm run preview:starters` (optionally `-- --no-scripts`) after building. It loads four disposable snapshots, not normal local seed data. Never apply `data/phase5/local-starters.sql` remotely; use the reviewed editorial workflow with real allocated IDs. Runbooks remain `type: implementation-guide` with `body.variant: operational-runbook`; deploy compatible readers before publication and retain variant support during rollback. See [compatibility and publication gates](docs/phase5/curated-expansion.md).

[CI](.github/workflows/verify.yml) runs runtime tests, strict types/import boundaries, catalog integrity/repeat-run checks, generated types, Astro check/build, built-Worker/artifact/example tests, and a deployment dry run without credentials. It never applies remote migrations or deploys.

### Phase 6 release preparation

The [rehearsal and rollout runbook](docs/phase6/rehearsal-and-rollout.md) separates local tooling from actual approvals/live evidence. `release:rehearse` requires an approved full export, consistent allocator capture, verified schema baseline and a new private output directory; it never contacts Cloudflare or refreshes the public seed. `CF_STAGING_CONFIG` accepts only a validated private isolated configuration and builds into `dist-staging/`; ordinary build/deploy commands remain production-targeted and still need approval. `release:smoke` requires an explicit approved HTTPS target and uses anonymous read methods only. An approved current private copy has now passed offline and isolated local D1/workerd rehearsal; exact-deployed-artifact rollback, independent review, staging and live Access/cache/purge/browser gates remain open. Production is still on migration 0005; no remote mutation/deployment occurred in that review.

[Post-roadmap local hardening](docs/phase6/development-hardening.md) corrects the recorded v1 long-search HTTP 500 without changing its normalization or searchable fields. Targeted patched Wrangler/Vitest/plugin updates also remove the recorded audit findings: the app and isolated prototype currently pass full and production-only audits with zero reported vulnerabilities. These changes are verified locally, not deployed; clean audits do not replace independent review or release approval.

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

**Local additions, not deployed:** `GET /api/v2/entries` returns paginated published summaries; `/api/v2/entries/{id}` returns selective details; `/api/v2/facets` returns populated conjunctive counts. See [the contract and release gates](docs/phase2/model-and-read-api.md) and [v2 OpenAPI](public/openapi-v2.json). Imported practices retain IDs and use a schema-version-0 adapter without invented taxonomy, maturity or verification dates. Published typed entries have HTML/Markdown canonical pages and join full exports, but remain excluded from v1. [Phase 4](docs/phase4/editorial-workflow.md) adds `/dashboard/editorial` and protected `/dashboard/api/catalog…` draft/review/publication routes with explicit private roles, optimistic versions and durable mutation receipts. No live grants or publications are implied; see [editorial OpenAPI](public/openapi-editorial.json).

| Endpoint                           | Description                                                                                         |
| ---------------------------------- | --------------------------------------------------------------------------------------------------- |
| `GET /api/practices`               | All practices. Optional filters: `search`, `categoryId`, `featureId`, `area`, `level`, `impact`     |
| `GET /api/categories`              | Categories                                                                                          |
| `GET /api/features`                | Cloudflare features                                                                                 |
| `GET /catalog`, `/families/{slug}` | Bounded SSR listings; URL-based v2 query state; populated families only                             |
| `GET /practices/{id}`              | Full practice HTML; send `Accept: text/markdown` for Markdown                                       |
| `GET /openapi.json`                | Public read-only API schema; [human-readable documentation](https://db.automatic-demo.com/api-docs) |
| `POST /dashboard/api/practices`    | Create a practice (Access-protected, JSON body)                                                     |

Dynamic document routes and JSON API reads support GET, HEAD, and OPTIONS. Public read resources allow anonymous cross-origin access. A 429 response includes `Retry-After: 60`. The API schema documents filters and nullable fields; UI query names differ from API parameters.

Dashboard writes require JSON of at most **64 KiB in bytes** and a random `Idempotency-Key` (16–128 letters, digits, hyphens, or underscores). Retry unchanged data with the same key: the API returns the original `201` and ID, or `409` if the completed key's normalized data differs. Keys are scoped to the verified Access identity (user subject or signed service-token identity) and retained durably. The dashboard keeps its key across retries/tab reloads, without storing form contents. See [the write contract](public/auth.md) for reset/storage limitations. Writes are same-origin only and responses are `no-store`.

## SEO, AEO, and agent access

Public HTML is indexable and readable without JavaScript. The homepage includes selected summaries and preserved legacy bookmark links, not all bodies. `/catalog` provides bounded discovery; each `/practices/{id}` page includes full content, applicability, configuration, sources/freshness, canonical/Open Graph metadata, and TechArticle/Breadcrumb structured data. Copy and theme controls are optional enhancements.

```bash
curl -H 'Accept: text/markdown' https://db.automatic-demo.com/
curl -H 'Accept: text/markdown' https://db.automatic-demo.com/practices/1
curl 'https://db.automatic-demo.com/api/practices?search=WAF&area=Security'
```

`/`, `/catalog`, populated `/families/{slug}`, `/practices/{id}`, and `/api-docs` default to HTML, support Markdown negotiation, and send `Vary: Accept`. Explicit Markdown is available regardless of Accept:

| Resource                                     | Purpose                                                           |
| -------------------------------------------- | ----------------------------------------------------------------- |
| `/index.md`, `/llms-full.txt`                | Complete repository content as `text/markdown`                    |
| `/practices/{id}.md`                         | Full details of one practice as `text/markdown`                   |
| `/catalog.md`, `/families/{slug}.md`         | Same effective bounded listing, preserving meaningful query state |
| `/llms.txt`                                  | Live agent index with practice URLs and usage instructions        |
| `/sitemap.xml`                               | Live canonical HTML URLs and recorded practice modification dates |
| `/api-docs`, `/api-docs.md`, `/openapi.json` | API documentation and machine-readable contract                   |
| `/.well-known/api-catalog`                   | RFC 9727 API discovery (`application/linkset+json`)               |
| `/.well-known/ai-catalog.json`               | Draft ARD capability discovery pointing to real public resources  |
| `/.well-known/agent-skills/index.json`       | Discoverable read-practices skill with verified SHA-256 digest    |
| `/auth.md`                                   | Anonymous read access and Access-protected contribution guidance  |

Link response headers advertise canonical/Markdown URLs, sitemap, API catalog, schema, and documentation. Supporting browsers can discover feature-detected read-only legacy and v2 catalog WebMCP search tools. Full Markdown exports and dynamic discovery iterate published snapshots in bounded batches rather than downloading all bodies at once.

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

Local seeding also applies the re-runnable `data/catalog-taxonomy.sql` and `data/phase5-products.sql` label seeds. They do not classify or publish practices; opt-in native starter snapshots are excluded. See the [119-record classification audit](docs/phase5/legacy-audit.md), which preserves old IDs/bodies/caveats without inventing verification. The public-seed refresh command takes an existing private full SQL export, performs no remote operations itself, and allowlists only legacy public tables plus current published typed snapshots, lifecycle, associations and sources. Drafts, unpublished/old revisions, draft-only reservations, private roles/reviews/contributors/receipts, and private high-water counters are excluded. It requires the current schema through migration `0007`; never use the public seed as a production recovery backup.

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
