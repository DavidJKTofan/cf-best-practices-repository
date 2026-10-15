# AGENTS.md

Guidance for AI coding agents working on this repository. See [README.md](README.md) for setup.

## Project

Cloudflare Worker + D1 app. Vanilla frontend/templates in `public/` (no frontend build step, no framework), gateway/API in `src/index.js`, shared projection in `src/practice-data.ts`, public document routes in `src/public-content.ts`, rendering in `src/content-rendering.ts`, negotiation in `src/content-negotiation.ts`, schema in `migrations/`, content updates in `data/`, tests in `test/`. New Worker modules use TypeScript.

## Commands

| Task                     | Command                                                                        |
| ------------------------ | ------------------------------------------------------------------------------ |
| Local dev                | `npm run dev` (copy `.dev.vars.example` to `.dev.vars` for local writes)       |
| Tests                    | `npm test` (Vitest + `@cloudflare/vitest-plugin`, runs in workerd)             |
| Type check               | `npm run typecheck` (TypeScript modules + generated Worker types)              |
| Regenerate binding types | `npm run cf-typegen` (after any `wrangler.jsonc` binding change)               |
| Apply migrations         | `npm run db:migrate:local` / `npm run db:migrate:remote`                       |
| Refresh seed data        | `npm run db:seed:refresh` (exports production data into `initial_data.sql`)    |
| Deploy check             | `npx wrangler deploy --dry-run`                                                |
| Format                   | `npx prettier --write <files>` (`.prettierrc`: tabs, single quotes, width 140) |

## Invariants

- **Keep file assets free; scope document routing.** `assets.run_worker_first` explicitly lists `/`, `/index.md`, `/practices/*`, `/sitemap.xml`, `/llms.txt`, `/llms-full.txt`, `/api-docs`, `/api/*`, and `/dashboard/api/*`. The document exceptions are required for server rendering and Markdown negotiation and incur Worker invocations. CSS, JS, images, and static discovery files stay asset-first/free. Do not set `run_worker_first: true` or enable Workers Cache on `default` ([pricing](https://developers.cloudflare.com/workers/cache/#pricing)).
- **Reads go through `PublicReads`.** The uncached default entrypoint rate-limits, then forwards public GET/HEAD reads via `ctx.exports.PublicReads.fetch()`. API routes go in `READ_ROUTES`; document routes in `isPublicContent`/`servePublicContent`, plus the explicit Worker-first list. Every D1-derived representation carries the shared `practices` cache tag (taxonomy uses `taxonomy`).
- **Reads use `withSession('first-primary')`.** Cache fills right after a write-triggered purge must not come from a lagging read replica, or stale data is cached for the whole edge TTL.
- **Writes must purge.** Purges are scoped per entrypoint, so writes call the `PublicReads.purgePractices()` RPC method after the D1 write. `wrangler dev` does not emulate Workers Cache (`ctx.cache` is undefined); verify `Cf-Cache-Status` after deploying.
- **Writes live under `/dashboard/api/*` only.** That path is behind Cloudflare Access, and the Worker validates the `Cf-Access-Jwt-Assertion` JWT (`ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`). Never add write routes under `/api/`.
- **Schema changes = new migration file.** Never edit an applied migration. Run `PRAGMA optimize` after index changes (`create_d1_schema.sh` does).
- **Content changes = re-runnable SQL in `data/`** (not migrations, which tests apply to an empty database). Validate with `--local` first, then `npx wrangler d1 execute DB --remote --file=...`. Direct D1 edits bypass the cache purge; redeploy or wait for the edge TTL.
- **Content must be sourced and plan-aware.** Verify fields, functions, phases, actions, and prerequisites against current docs. Preserve practice IDs. Dry run validates configuration, not traffic matches; Log is Enterprise-only, and browser challenges are unsuitable for APIs. Apply the data file twice to check idempotency (including `updated_at`), then refresh `initial_data.sql` only after remote application.
- **Never set `remote: true` on the `DB` binding.** Local development must not touch production data.
- **Rehearse remote D1 changes on a production copy.** Production tables predate the migrations, and local/test databases are built from them, so a change that passes locally can still fail remotely. Export with `npx wrangler d1 export DB --remote --output=prod.sql`, load it with `--local --persist-to=<tmp dir>`, and apply migrations and data files there first. Take a Time Travel bookmark (`npx wrangler d1 time-travel info DB`) before remote writes.
- **Report caught errors with `console.error(err)`** (the error object, not a string) so [Workers Issues](https://developers.cloudflare.com/workers/observability/issues/) can group them by exception and stack.
- **Public SEO and AI retrieval are intentional.** Allow public HTML indexing and AI answer retrieval: `search=yes, ai-input=yes, ai-train=no`. Keep dashboard/404 pages and JSON API responses `noindex`; do not apply a site-wide noindex. `robots.txt` allows public API reads, blocks `/dashboard` and `/cdn-cgi/`, and blocks training crawlers separately from search/user agents. Zone-managed robots and bot blocking must agree with this policy.
- **Preserve owner-approved security policy.** Respect the published crawler policy and existing account-level client restrictions. Use validated Bot Management fields such as `cf.bot_management.detection_ids` for crawler identification; do not infer identities from generic labels, shared fingerprints, or an entire AI Crawler category. Scope exceptions to public GET/HEAD/OPTIONS on the intended hostname, excluding dashboard and `/cdn-cgi/`, and exclude blocked identities from exceptions. Preserve terminating blocks before exemptions and skip only the responsible mitigation. Inspect the target configuration and confirm changes with the owner, then dry-run each mutation before applying it; validation does not establish real traffic matches. See [deployment guidance](docs/agent-readiness.md#deployment-guidance).
- **Keep documentation public-safe.** Use generic examples or placeholders for deployment-specific identifiers. Keep live security-rule inventories, exact production expressions and thresholds, non-public detection mappings, raw telemetry, and recovery bookmarks out of public documentation.
- **Content must work without JavaScript.** Render homepage links/summaries and complete `/practices/{id}` pages from D1. Preserve old `/#practice-<id>` anchors, but use stable practice paths for canonical citations. Include accurate metadata, escaped JSON-LD, and sourced freshness dates. Sitemap lists canonical HTML URLs only, not filters, APIs, Markdown aliases, or infrastructure paths.
- **Negotiate representations safely.** `/`, `/practices/{id}`, and `/api-docs` default to HTML and serve `text/markdown; charset=utf-8` for an explicitly preferred `Accept: text/markdown` (respect q values and exclusions). Set `Vary: Accept` on both variants. Normalize Accept and remove UI queries before the cached entrypoint; Workers Cache honors Vary. Explicit `/index.md`, `/practices/{id}.md`, and `/llms-full.txt` remain Markdown regardless of Accept. Do not reuse static-shell validators on D1-rendered HTML.
- **Keep discovery accurate.** Maintain `/llms.txt`, `/llms-full.txt`, `/sitemap.xml`, `/openapi.json`, `/api-docs` (+ `.md`), `/auth.md`, RFC 9727 `/.well-known/api-catalog`, `/.well-known/ai-catalog.json`, and the agent skill/index. After editing SKILL.md, update its SHA-256 digest (`shasum -a 256 public/.well-known/agent-skills/read-practices/SKILL.md`); tests verify the served bytes. Public reads require no credentials. Publish auth/protocol metadata only for implemented services. WebMCP is feature-detected and exposes only read-only search.
- **Frontend safety.** Render client data with DOM APIs and `textContent`; never `innerHTML` with API data. Server HTMLRewriter insertion accepts only escaped renderer output; escape text/attributes, allow only HTTP(S) source URLs, and escape `<` in JSON-LD. Markdown must escape prose and use fences longer than any backtick runs in stored configuration.
- Static asset headers belong in `public/_headers`; Worker responses set headers in code.

## Debugging

Use the right tool for the environment:

| Need                                          | Tool                                                                                                                                                 |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Local data, logs, and traces (`wrangler dev`) | [Local Explorer](https://developers.cloudflare.com/workers/local-development/local-explorer/) UI at `/cdn-cgi/local/explorer` (press `e`) or its API |
| Production errors                             | Workers Issues (dashboard > Worker > Issues), enabled via `observability.issues` in `wrangler.jsonc`                                                 |
| Production logs and traces                    | Workers Observability MCP server                                                                                                                     |
| Account configuration (Access app, zone)      | Cloudflare API MCP server (read before changing; confirm writes with the owner)                                                                      |
| Product facts                                 | Cloudflare Documentation MCP server                                                                                                                  |

Local Explorer API (OpenAPI spec: `curl http://localhost:8787/cdn-cgi/local/explorer/api`):

```bash
# Run SQL against the local D1 database (single statement, or {"batch": [...]})
# Set DATABASE_ID to the database identifier shown in Local Explorer.
curl -X POST "http://localhost:8787/cdn-cgi/local/explorer/api/d1/database/${DATABASE_ID}/raw" \
  -H 'Content-Type: application/json' -d '{"sql":"SELECT COUNT(*) FROM BestPractices"}'

# Query captured traces and logs with read-only SQL (tables: spans, logs; root spans have parent_id IS NULL)
curl -X POST http://localhost:8787/cdn-cgi/local/explorer/api/local/observability/query \
  -H 'Content-Type: application/json' \
  -d '{"sql":"SELECT name, duration_ms, json_extract(json(attributes), ?) FROM spans WHERE parent_id IS NULL ORDER BY start_ms DESC LIMIT 10","params":["$.\"url.full\""]}'
```

Local caveats: `wrangler dev` rewrites `request.url` to the production hostname, sets `CF-Connecting-IP` to a loopback address, and does not emulate Workers Cache (no `Cf-Cache-Status`, `ctx.cache` is undefined). It also rewrites Link response URLs to localhost while HTML canonicals retain the production URL; local Lighthouse reports this canonical mismatch. Verify canonical agreement on the deployed hostname.

## MCP servers

| Server                     | URL                                            | Use                                     |
| -------------------------- | ---------------------------------------------- | --------------------------------------- |
| Cloudflare Documentation   | `https://docs.mcp.cloudflare.com/mcp`          | Verify Workers, D1, Cache, Access facts |
| Cloudflare API (Code Mode) | `https://mcp.cloudflare.com/mcp`               | Inspect or change account resources     |
| Workers Bindings           | `https://bindings.mcp.cloudflare.com/mcp`      | Query D1, manage bindings               |
| Workers Observability      | `https://observability.mcp.cloudflare.com/mcp` | Workers Logs and traces for this Worker |

Catalog: [MCP servers for Cloudflare](https://developers.cloudflare.com/agents/model-context-protocol/cloudflare/servers-for-cloudflare/).

## References

- Docs indexes for agents: [Workers llms.txt](https://developers.cloudflare.com/workers/llms.txt), [D1 llms.txt](https://developers.cloudflare.com/d1/llms.txt) (append `index.md` to any docs URL for Markdown)
- [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/)
- [Agent-readiness implementation review](docs/agent-readiness.md) · [Live readiness report](https://isitagentready.com/db.automatic-demo.com) · [Cloudflare AEO](https://blog.cloudflare.com/aeo/) · [Improve SEO](https://developers.cloudflare.com/fundamentals/performance/improve-seo/) · [`/cdn-cgi/` exclusions](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/)
- [2026-10-15 content review](data/content-review-2026-10-15.md) · [Rulesets dry run](https://developers.cloudflare.com/ruleset-engine/rulesets-api/dry-run/) · [Rules fields](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/) · [Rate limiting availability](https://developers.cloudflare.com/waf/rate-limiting-rules/#availability)
- [Workers Cache](https://developers.cloudflare.com/workers/cache/) · [Cache D1 reads](https://github.com/cloudflare/cloudflare-docs/blob/f336f6e48ba743477adae2d47e75244a26c6fee0/src/content/docs/d1/best-practices/cache-d1-reads.mdx) · [Purge](https://developers.cloudflare.com/workers/cache/purge/)
- [Static Assets billing](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/) · [`_headers`](https://developers.cloudflare.com/workers/static-assets/headers/)
- D1: [query](https://developers.cloudflare.com/d1/best-practices/query-d1/) · [indexes](https://developers.cloudflare.com/d1/best-practices/use-indexes/) · [retries](https://developers.cloudflare.com/d1/best-practices/retry-queries/) · [import/export](https://developers.cloudflare.com/d1/best-practices/import-export-data/) · [migrations](https://developers.cloudflare.com/d1/reference/migrations/)
- [Validate Access JWTs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Install/update Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/) · [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/)
- [Local Explorer](https://developers.cloudflare.com/workers/local-development/local-explorer/) · [D1 local development](https://developers.cloudflare.com/d1/best-practices/local-development/) · [Workers Issues](https://developers.cloudflare.com/workers/observability/issues/)
