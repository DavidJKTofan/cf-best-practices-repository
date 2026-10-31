# Catalog scalability and production-readiness review

> Historical pre-rollout evidence: the local-only checkpoint below preceded a separately approved production release. See [2026-10-31 rollout results](../rollout-2026-10-31.md) for applied 0006–0007, the successful Astro/v2 deployment and targeted live checks. The earlier scan score and 404 observations below describe the old deployment, not the new release.

**Checkpoint: 2026-10-31. Local implementation and private-copy rehearsal verified; no production migration or deployment.** The owner approved a private production backup and local rehearsal while retaining independent-review/staging/live gates. No Access changes, live roles, native publication, fixture SQL, seed refresh, DNS change, commit or push occurred.

## Pagination and direct filtering

- Catalog/family HTML and `/api/v2/entries` already use server pagination: **20 summaries by default, at most 50**, with stable title/ID or editorial-date/ID ordering, totals and next/previous links. Page numbers are capped at 10,000. Filter changes reset the page. A new built-Worker regression traverses every page of an unchanged fixture catalog without duplicate/missing IDs and verifies the limit and absence of detail bodies. Separate requests are not a frozen snapshot: concurrent publications/edits can shift offset-page membership.
- `public/catalog-search.js` progressively enhances the same SSR GET forms: **350 ms text debounce**, immediate select updates, cancellation and latest-request-wins protection, IME composition handling, and a ten-second request timeout. It replaces escaped server-rendered results/facets, preserves focus/caret/disclosure state, updates canonical/Markdown/Open Graph/structured metadata and effective URL history, and supports Back/Forward. Consecutive typing replaces its current history entry rather than adding an entry per response.
- On failure, retain the last good results and current form; announce that Search will use native navigation. Search, clear links, pagination and full reading remain functional without JavaScript. The enhancement is only loaded on catalog/family pages and remains an asset-first file; no new API or write route was added.
- This is bounded **response size**, not constant query cost. Substring `instr` search, exact totals/facet aggregation, union-view sorting and deep `OFFSET` pages can scan/sort increasing numbers of rows. Title/summary search uses SQLite's ASCII case folding, not multilingual full-text relevance. No large-catalog/concurrent-load benchmark was performed. Measure D1 rows read, SQL duration, cold/warm latency and deep pages as content grows; use that evidence to design a separately reviewed full-text index and keyset/cursor contract. Do not silently change literal-search or pagination semantics.
- The compatibility `/api/practices` endpoint still returns all matching legacy bodies. Existing clients remain supported, but it is not the scalable replacement for summary discovery. Prefer v2 after its approved release and retrieve full details selectively.

## Production D1 and actual local rehearsal

Read-only inspection found **119 production practices**, applied migrations **0001–0005**, the intended Worker/D1 binding, `quick_check = ok` and no foreign-key violations. Migrations **0006–0007 remain pending remotely**. A full private export, separately captured allocator state unchanged before/after export, and a Time Travel bookmark were retained outside the repository with restricted permissions.

The first offline rehearsal stopped correctly on its preservation comparison: only derived `sqlite_stat1` optimizer data changed after index creation/optimization. The checker now excludes exactly `sqlite_stat1`/`sqlite_stat4` (and separately checks allocator floors); it still compares all application/private tables. A synthetic analyzed-database/private-table regression guards against broad exclusions. The failed copy was retained; a new offline rehearsal passed all pending migrations, twice-applied ordinary patches, private recovery, old SQL and sanitized-export parity checks.

Next, imported the full approved export into **new private local D1/workerd storage**, restored captured allocator floors, and actually applied **0006–0007** and the four ordinary patches twice with explicit `--local --persist-to`. Compared the resulting database to the offline upgraded copy: application/private data matched, allocator floors held, the ledger had seven migrations, and `PublishedCatalog` selected the same 119 legacy entries. No fixture or role was loaded into this retained upgraded copy or normal local storage.

**40 actual local runtime assertions** then passed on a separate disposable private branch:

- Recorded prior v0.8 source: public reads, signed creation, unchanged replay, changed-data conflict, authentication denial, and foreign-key failure without practice/receipt/allocator effects.
- Current built Worker: cross-version replay/conflict, bounded catalog reads, anonymous/ungranted editorial denials, private/no-store preview, distinct-author/reviewer/publisher workflow, publication replay, and HTML/Markdown/JSON runbook reads with v1 exclusion.
- Closed and copied that full local state to a new recovery directory, then restarted the current Worker and verified recovered allocator/receipt counts, legacy replay, publication replay and the operational-runbook body variant.

Only synthetic local identities/roles/entries were used on probe branches. An initial probe correctly failed publication for a fixture's unregistered product; retained the failed branch and reran on a fresh branch with registry-compatible runbook content. No application workaround or production fixture publication was introduced. Wrangler's local export command does not accept `--persist-to`; private comparison/snapshot used read-only SQLite access/backup after the local CLI exited, rather than touching ordinary state.

**Limits:** v0.8 is the recorded prior source, built with current local dependencies, not an independently matched downloaded production bundle. This does not close exact-artifact rollback review. Local JWKS verification is not live Access policy testing; local Workers Cache is not edge-cache/purge propagation. File-state recovery is not a production Time Travel restore. Independent schema/security/source/dependency review, approved isolated staging and live gates remain open.

## Verification

| Check                                                                       | Result                                    |
| --------------------------------------------------------------------------- | ----------------------------------------- |
| Runtime tests in workerd                                                    | **213/213**                               |
| Built frontend/artifact/example/controller checks                           | **36/36**                                 |
| Strict TypeScript, import/public artifact boundaries, discovery             | Pass; **7 boundary + 3 discovery** checks |
| Content integrity, four patches twice, starter SQL parity                   | Pass; **5 + 5** Python tests              |
| Synthetic release tooling                                                   | **9 Python + 7 Node** checks              |
| Astro check/build, generated binding types, generated-config deploy dry run | Pass; **0 Astro errors/warnings/hints**   |
| Root npm audit                                                              | **0 findings**                            |
| Current-copy offline + actual local D1 migration rehearsal                  | Pass, with limitations above              |

Chrome DevTools checked successful direct search on catalog/family pages in **20 page/viewport/theme combinations**: 320/390/768/1440/3840 px, light/dark. No document overflow; focus, page reset and family locking held. Additional targeted journeys verified caret/disclosure preservation, immediate selects, canonical/Markdown/Open Graph updates, Back/Forward, a deliberately delayed stale response, simulated network failure and subsequent successful native GET submission. IME generated zero queries during composition and one after completion. Native script-blocked search at 320 px also returned complete results without overflow. These are targeted Chromium checks, not full cross-browser/assistive-technology certification; earlier reading/copy evidence remains in [frontend simplification](frontend-simplification.md).

Unthrottled local catalog trace: **LCP 63 ms, TTFB 10 ms, CLS 0.00**; no CrUX data. Render-blocking/cache insights estimated zero FCP/LCP savings. All seven listed document/CSS/script requests returned 200, with no console warnings/errors on the clean catalog journey. These numbers describe a loopback fixture preview, not production, concurrent traffic or large-catalog performance.

## Agent/API readiness and production recheck

Reviewed the [Agent Readiness](https://blog.cloudflare.com/agent-readiness/) and [AEO](https://blog.cloudflare.com/aeo/) guidance, and ran [isitagentready.com](https://isitagentready.com/) against the **existing production deployment**, not the new local build:

- Content profile: **Level 5/5 — Agent-Native**; DNS-AID discovery is missing. No DNS mutation was attempted.
- Separate selected discovery checks passed robots/sitemap/Link relations, Markdown negotiation, AI crawler rules/Content Signals, API catalog, agent skills, WebMCP and the capability manifest. `authMd` failed because the old H1 did not contain `auth.md`. Corrected that heading locally and added a regression; did not invent OAuth, registration, MCP or A2A services.
- Final public-read recheck: homepage, v1 API, practice HTML/explicit Markdown, auth guidance and OpenAPI returned 200; `/catalog` and `/api/v2/entries` still returned **404**, confirming the new release is not live. V1 still returned 119 practices; practice 18's canonical agreed with its production URL. The old auth heading still fails the scanner condition until deployment.

SSR full reading, stable citations, explicit/negotiated Markdown, sourced applicability/freshness, public-only schemas, discovery and read-only optional browser tooling support retrieval. A scanner level is **not** full API certification, evidence of search-engine indexing/AI citations, a guarantee of crawler access for every identity, or proof of factual correctness. The v2 publication boundary and editorial authorization have local tests; they are not yet a production API service.

## Release disposition and exact next action

**Production remains unchanged.** Obtain independent review of the exact source/artifact/dependencies, reconcile the exact deployed compatible recovery artifact, and approve specific separate staging resources/Access design. Then execute staging signed/public/browser/cache journeys without uploading the private production backup. Only after retained gates and exact production approval are satisfied: refresh the private recovery capture, apply approved migrations/ordinary patches, deploy the reviewed generated configuration, and verify production HTML/Markdown/v1/v2/discovery, authentication and cache/purge behavior. Do not refresh the seed until approved remote verification. See the [release runbook](rehearsal-and-rollout.md).
