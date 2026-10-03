# AGENTS.md

Guidance for AI coding agents working on this repository. See [README.md](README.md) for setup.

## Project

Cloudflare Worker + D1 app. Static frontend in `public/` (no build step, no framework), API in `src/index.js`, schema in `migrations/`, content updates in `data/`, tests in `test/`.

## Commands

| Task                     | Command                                                                        |
| ------------------------ | ------------------------------------------------------------------------------ |
| Local dev                | `npm run dev` (copy `.dev.vars.example` to `.dev.vars` for local writes)       |
| Tests                    | `npm test` (Vitest + `@cloudflare/vitest-plugin`, runs in workerd)             |
| Regenerate binding types | `npm run cf-typegen` (after any `wrangler.jsonc` binding change)               |
| Apply migrations         | `npm run db:migrate:local` / `npm run db:migrate:remote`                       |
| Deploy check             | `npx wrangler deploy --dry-run`                                                |
| Format                   | `npx prettier --write <files>` (`.prettierrc`: tabs, single quotes, width 140) |

## Invariants

- **Keep static assets free.** The Worker runs only for `assets.run_worker_first` paths (`/api/*`, `/dashboard/api/*`). Do not set `run_worker_first: true` and do not enable Workers Cache on the `default` entrypoint ([pricing](https://developers.cloudflare.com/workers/cache/#pricing)).
- **Reads go through `PublicReads`.** The uncached default entrypoint rate-limits, then forwards `GET /api/*` via `ctx.exports.PublicReads.fetch()`. New read routes go in `READ_ROUTES` with a `Cache-Tag`.
- **Writes must purge.** Purges are scoped per entrypoint, so writes call the `PublicReads.purgePractices()` RPC method after the D1 write. `wrangler dev` does not emulate Workers Cache (`ctx.cache` is undefined); verify `Cf-Cache-Status` after deploying.
- **Writes live under `/dashboard/api/*` only.** That path is behind Cloudflare Access, and the Worker validates the `Cf-Access-Jwt-Assertion` JWT (`ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`). Never add write routes under `/api/`.
- **Schema changes = new migration file.** Never edit an applied migration. Run `PRAGMA optimize` after index changes (`create_d1_schema.sh` does).
- **Content changes = re-runnable SQL in `data/`** (not migrations, which tests apply to an empty database). Validate with `--local` first, then `npx wrangler d1 execute DB --remote --file=...`. Direct D1 edits bypass the cache purge; redeploy or wait for the edge TTL.
- **Never set `remote: true` on the `DB` binding.** Local development must not touch production data.
- **Rehearse remote D1 changes on a production copy.** Production tables predate the migrations, and local/test databases are built from them, so a change that passes locally can still fail remotely. Export with `npx wrangler d1 export DB --remote --output=prod.sql`, load it with `--local --persist-to=<tmp dir>`, and apply migrations and data files there first. Take a Time Travel bookmark (`npx wrangler d1 time-travel info DB`) before remote writes.
- **Report caught errors with `console.error(err)`** (the error object, not a string) so [Workers Issues](https://developers.cloudflare.com/workers/observability/issues/) can group them by exception and stack.
- **No indexing / no AI use.** Keep `X-Robots-Tag: noindex, nofollow` (`public/_headers`, `API_HEADERS`), robots meta tags, and `public/robots.txt` Content Signals.
- **Frontend safety.** Render data with DOM APIs and `textContent`; never `innerHTML` with API data.
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
curl -X POST http://localhost:8787/cdn-cgi/local/explorer/api/d1/database/fff37b78-990d-423c-a110-5cf786549f6f/raw \
  -H 'Content-Type: application/json' -d '{"sql":"SELECT COUNT(*) FROM BestPractices"}'

# Query captured traces and logs with read-only SQL (tables: spans, logs; root spans have parent_id IS NULL)
curl -X POST http://localhost:8787/cdn-cgi/local/explorer/api/local/observability/query \
  -H 'Content-Type: application/json' \
  -d '{"sql":"SELECT name, duration_ms, json_extract(json(attributes), ?) FROM spans WHERE parent_id IS NULL ORDER BY start_ms DESC LIMIT 10","params":["$.\"url.full\""]}'
```

Local caveats: `wrangler dev` rewrites `request.url` to the production hostname, sets `CF-Connecting-IP` to a loopback address, and does not emulate Workers Cache (no `Cf-Cache-Status`, `ctx.cache` is undefined).

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
- [Workers Cache](https://developers.cloudflare.com/workers/cache/) · [Cache D1 reads](https://github.com/cloudflare/cloudflare-docs/blob/f336f6e48ba743477adae2d47e75244a26c6fee0/src/content/docs/d1/best-practices/cache-d1-reads.mdx) · [Purge](https://developers.cloudflare.com/workers/cache/purge/)
- [Static Assets billing](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/) · [`_headers`](https://developers.cloudflare.com/workers/static-assets/headers/)
- D1: [query](https://developers.cloudflare.com/d1/best-practices/query-d1/) · [indexes](https://developers.cloudflare.com/d1/best-practices/use-indexes/) · [retries](https://developers.cloudflare.com/d1/best-practices/retry-queries/) · [import/export](https://developers.cloudflare.com/d1/best-practices/import-export-data/) · [migrations](https://developers.cloudflare.com/d1/reference/migrations/)
- [Validate Access JWTs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Install/update Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/) · [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/)
- [Local Explorer](https://developers.cloudflare.com/workers/local-development/local-explorer/) · [D1 local development](https://developers.cloudflare.com/d1/best-practices/local-development/) · [Workers Issues](https://developers.cloudflare.com/workers/observability/issues/)
