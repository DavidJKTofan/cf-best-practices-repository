# Project documentation

[Project overview & local setup](../README.md) · [Contributor rules](../AGENTS.md) · [Live guide](https://db.automatic-demo.com)

## Production checkpoint — 2026-11-11

**Serving release:** owner-requested new-tab links and neutral Levels, built from **uncommitted local changes on `9024693` (`v1.2`)**, deployed at 100% traffic as version `72bae87e-8c70-4f6b-a6e2-f349a738bc24`. Deployment used the verified local Astro build, generated `dist/server/wrangler.json` and Wrangler `--strict`; existing Workers Builds is unchanged. See [source, version and deployment evidence](rollout-2026-11-11-v1.2.md#new-tab-and-neutral-level-follow-up).

**UI verification is incomplete:** the latest unchanged full smoke passes **10/10**, including anonymous denial, filters, discovery and independent HITs. Homepage/catalog/practice 1 pass **30** live viewport/theme combinations. However, `/practices/18` still returns older cached HTML with same-tab links and its previous stylesheet URL, which now returns **404**. Fresh practice 1/2 responses use the new links/CSS. This cache/deployment discrepancy needs owner-led investigation and separately approved remediation; a passing representation smoke does not certify UI freshness.

- Public reads confirm **119 legacy/published practices**. Private drafts, roles and revisions were not re-inspected; zero native state was last established during the initial private inspection.
- This UI release changed no D1 data, schema, bindings, cache or security policy. The [initial scoped release](rollout-2026-10-31.md) applied migrations 0006–0007; [v1.1](rollout-2026-10-31-v1.1.md) remains historical evidence.
- Independent review, isolated staging, exact-artifact recovery, authenticated mutations/retries, purge propagation and operational sign-off remain open. Scoped deployment approval does not close these gates.
- Pilots and four curated starters are disposable local fixtures, not production publications. Live native publication and role provisioning need separate review, rehearsal and approval.
- Fresh preflight passed **226 runtime + 42 built frontend** tests and the full checks in the release record. Local targeted browser coverage passed **40** viewport/theme/script-mode combinations; all four Levels are neutral in both themes and Markdown/footer clicks open safe new tabs.
- Earlier v1.2 smoke failed anonymous denial with **429**; the first follow-up smoke failed the homepage group. Neither failure reproduced in the latest complete run, and their causes remain unestablished. No assertion or security control was relaxed.

This is a dated checkpoint, not a live status endpoint. Use the [release runbook](phase6/rehearsal-and-rollout.md), [operational acceptance checklist](phase6/operational-acceptance.md) and [roadmap](cloudflare-platform-roadmap.md) for remaining gates and next actions.

## Documentation map

| Topic                                           | Reference                                                                                                                                     |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Roadmap, decisions and progress                 | [Catalog expansion](cloudflare-platform-roadmap.md)                                                                                           |
| Module ownership                                | [Phase 1 boundaries](phase1/module-boundaries.md)                                                                                             |
| Published model and v2 read API                 | [Phase 2 contracts](phase2/model-and-read-api.md)                                                                                             |
| Astro presentation and local pilots             | [Phase 3 frontend](phase3/frontend-and-pilots.md)                                                                                             |
| Private editorial roles, review and publication | [Phase 4 workflow](phase4/editorial-workflow.md)                                                                                              |
| Curated starters and publication gates          | [Phase 5 expansion](phase5/curated-expansion.md)                                                                                              |
| Legacy classification provenance                | [119-record audit](phase5/legacy-audit.md)                                                                                                    |
| Release preparation and recovery                | [Phase 6 runbook](phase6/rehearsal-and-rollout.md)                                                                                            |
| Accountable roles, monitoring and stop criteria | [Operational acceptance](phase6/operational-acceptance.md)                                                                                    |
| UI implementation and browser evidence          | [Simplification](phase6/frontend-simplification.md), [filters](phase6/filter-restoration.md), [compact catalog](phase6/compact-catalog-ui.md) |
| Search cost and production-copy evidence        | [Scalability review](phase6/scalability-and-production-readiness.md)                                                                          |
| Hardening and dependency checks                 | [Development hardening](phase6/development-hardening.md)                                                                                      |
| Public discovery and crawler policy             | [Agent readiness](agent-readiness.md)                                                                                                         |

## Architecture and public interfaces

- **Frontend:** Astro SSR pages/components/styles in `src/`, with small vanilla enhancements and dashboard files in `public/`. No hydrated UI framework or full-body catalog download. Public reading and filtering work without JavaScript.
- **Gateway:** `src/astro-worker.ts` exports the gateway and Astro-aware `PublicReads`; `src/index.ts` retains framework-independent regression exports. Thin Hono routes live in `src/api/`, queries in `src/modules/`, and policy in `src/platform/`.
- **Data:** D1 migrations live in `migrations/`; re-runnable content patches live in `data/`. `initial_data.sql` is a sanitized public snapshot, **never a recovery backup**. Legacy IDs remain stable; native published entries stay outside v1.
- **Caching:** the uncached gateway rate-limits before forwarding to cached `PublicReads`. Reads use `first-primary`; D1 representations share the `practices` purge tag. HTML/Markdown negotiation uses `Vary: Accept`. Static files stay asset-first; never enable cache on the default entrypoint or run the Worker first for every asset.
- **Freshness:** edge reads are fresh for one hour, with another 24 hours of stale-while-revalidate. Writes/replays await a purge attempt; failure does not undo the write, and browser caches are separate. Immediate global read-after-write visibility is not guaranteed.
- **Private writes:** only `/dashboard/api/*`, protected by Access plus Worker JWT validation. Editorial login additionally requires private role grants and exact-version independent review. Mutation responses/previews are private and `no-store`.

| Public resource                                                                                    | Purpose                                                                   |
| -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `/catalog`, `/families/{slug}`                                                                     | Bounded SSR search/filter/sort/page state; only populated families appear |
| `/practices/{id}`                                                                                  | Canonical HTML; negotiate Markdown with `Accept: text/markdown`           |
| `/api/v2/entries`, `/api/v2/entries/{id}`, `/api/v2/facets`                                        | Published summaries, selective detail and conjunctive facets              |
| `/api/practices`, `/api/categories`, `/api/features`                                               | Preserved legacy reads                                                    |
| `/index.md`, `/catalog.md`, `/families/{slug}.md`, `/practices/{id}.md`                            | Explicit Markdown, independent of Accept                                  |
| `/llms.txt`, `/llms-full.txt`, `/sitemap.xml`                                                      | Agent index, complete streamed Markdown and canonical HTML discovery      |
| `/api-docs`, `/api-docs.md`, `/openapi.json`                                                       | Human/machine API contracts                                               |
| `/.well-known/api-catalog`, `/.well-known/ai-catalog.json`, `/.well-known/agent-skills/index.json` | API, capability and verified agent-skill discovery                        |

Public reads need no credentials. See the [live API docs](https://db.automatic-demo.com/api-docs), [v2 schema](../public/openapi-v2.json), [editorial schema](../public/openapi-editorial.json) and [write/authentication contract](../public/auth.md) for exact parameters, limits, idempotency and authorization rules.

## Development and deployment

Start with the [root setup and checks](../README.md#local-development). For a fork, replace the Worker name, D1 identifiers, custom domain and Access issuer/audience in `wrangler.jsonc`, and update canonical/discovery URLs. Provision a separate database and Access application for staging; never set `remote: true` on `DB` for local development. Regenerate binding types with `npm run cf-typegen` after binding changes.

### Build and deploy configuration

| Workers Builds setting | Value                                                    |
| ---------------------- | -------------------------------------------------------- |
| Build command          | `npm run build`                                          |
| Deploy command         | `npx wrangler deploy --config dist/server/wrangler.json` |
| Root directory         | Repository root                                          |

These Git integration settings are configured in Cloudflare, not inferred from npm scripts. Plain `npx wrangler deploy` targets raw Astro source and fails on a clean checkout; do not add aliases for Astro virtual modules. `npm run deploy` builds first and deploys the generated configuration, but still requires explicit approval and the release gates. Never add automatic remote migrations, seeds or publication to Builds/CI.

[CI](../.github/workflows/verify.yml) is credential-free: runtime/types/boundaries/content/discovery/release checks, generated types, Astro check/build, built-Worker tests and deploy dry run only. Local Wrangler does not emulate Workers Cache; confirm HITs on an approved live target. Local Link headers may use localhost while HTML canonicals retain the production hostname; verify canonical agreement live.

### Disposable content previews

```bash
npm run build
npm run preview:pilots -- --no-scripts
# Or: npm run preview:starters -- --no-scripts
```

Startup prints normal and script-blocked URLs. Stop with Ctrl-C; the ephemeral public-seed/fixture data is not retained. Never apply `data/phase5/local-starters.sql` remotely. Runbooks use the `implementation-guide` operational-runbook body variant; keep variant-aware readers deployed before publication and during rollback.

### Release and data safety

- Rehearse remote D1 changes on an approved current production copy, with a private full backup/allocator capture and Time Travel bookmark. Keep private exports, receipts, roles and recovery records outside the repository.
- Validate content patches locally and twice for data/timestamp/sequence idempotency. Only after an approved remote application and verification, invalidate reads and refresh the public seed with `npm run db:seed:refresh -- /private/path/export.sql`.
- `release:rehearse` is offline and requires a new private output directory; it does not contact Cloudflare or refresh the seed. `CF_STAGING_CONFIG` requires an explicitly isolated private config and builds into `dist-staging/`; no staging resources are currently provisioned.
- Live `release:smoke` requires an explicit approved HTTPS target. `--expect-legacy-filters` adds six-filter parity/normalization/clear-link checks. The optional `--allow-cloudflare-bm-cookie` accepts only `__cf_bm`; no application cookie allowance or credential forwarding. Passing probes do not explain earlier intermittent failures or establish UI/cache freshness; retain diagnostics and involve the owner before remediation.
- Existing durable creation and expression upgrades are recorded in the [October 29 rollout](rollout-2026-10-29.md) and [October 22 rollout](frontend-rollout-2026-10-22.md). Preserve private retry receipts and apply prerequisites before compatible handlers; see [AGENTS.md](../AGENTS.md) and the runbook rather than treating historical commands as a new deployment plan.

## UI and content maintenance

Keep the minimal reference UI, exact system font stacks in [AGENTS.md](../AGENTS.md#frontend-design-and-maintenance), full summaries and bounded widths (1440px listings, 1120px reading). Desktop result columns start at a 68rem container; narrow lists stack. Domains alone use semantic colors with a legend; Levels use neutral gray and explicit labels. Empty sections/facets/journeys are omitted server-side, while selected empty filters remain clearable.

Markdown reading links and every footer anchor use `target="_blank" rel="noopener noreferrer"` in HTML, without JavaScript. Preserve effective Markdown queries and same-tab ordinary navigation. Catalog enhancements debounce text by 350ms, apply selects immediately and preserve focus/history; native GET forms remain usable. Pagination bounds response size, not substring/count/deep-offset query cost.

Content must cite current official sources and record prerequisites, product/phase/action availability, plan entitlements, maturity, limitations and rollback. Record fact-verification dates separately from editorial timestamps; do not invent taxonomy or freshness. Request-phase custom/rate-limiting Log requires Enterprise, and browser challenges are unsuitable for APIs. See the [October 29 review](../data/content-review-2026-10-29.md) and [earlier review](../data/content-review-2026-10-15.md).

Public indexing and AI answer retrieval are intentional: `search=yes, ai-input=yes, ai-train=no`. Preserve the published crawler restrictions, dashboard/infrastructure exclusions and owner-approved security controls. Inspect and obtain approval before policy changes; a dry run does not prove real traffic matches. Public JSON, dashboard and 404 responses remain `noindex`, not the whole site.

Keep this index/checkpoint, the [root README](../README.md) and [AGENTS.md](../AGENTS.md) synchronized. Historical release evidence stays dated; targeted checks are not full accessibility/cross-browser certification or operational acceptance. The [project disclaimer](../README.md#disclaimer) applies throughout.
