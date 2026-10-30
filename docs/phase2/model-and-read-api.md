# Phase 2: additive model and versioned reads

**Status:** core completed and verified locally on 2026-10-30; independent review and fresh private production-copy rehearsal remain open. Not staged or deployed. Owner directed Phase 2 continuation; no commit, push, remote write, deployment, or security-policy change authorized. The [roadmap](../cloudflare-platform-roadmap.md) remains the checkpoint.

**Historical phase boundary:** this records Phase 2's JSON-only native implementation. [Phase 3](../phase3/frontend-and-pilots.md) now adds local HTML/Markdown canonical pages and native-inclusive exports/discovery. References below to null native canonical paths and legacy-only document exports describe the Phase 2 checkpoint, not the current local presentation. v1 eligibility, legacy-conversion and production-copy gates remain unchanged.

## Model and compatibility decisions

Migration `0006_catalog_model.sql` is additive: no legacy table rebuild, column removal, receipt rewrite, or practice-ID change.

| Entity                               | Authority and public visibility                                                                                                      |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `CatalogEntries`                     | Stable numeric identity, optional same-ID legacy association, optional published revision pointer                                    |
| `CatalogRevisions`                   | Schema-version-1 shared metadata and bounded JSON body; not public just because it exists                                            |
| `CatalogRevisionTaxa`                | Revision-scoped family/product/outcome associations; a draft's associations cannot change public facets                              |
| `CatalogRevisionSources`             | Ordered public HTTP(S) sources scoped to a revision, not the editable entry                                                          |
| `CatalogPublications`                | Immutable publication history; composite foreign keys prevent cross-entry/unpublished pointer selection                              |
| `CatalogDrafts`                      | Private working envelope and optimistic version storage only; no authoring/preview API in this phase                                 |
| `CatalogTaxa`, `CatalogTaxonAliases` | Public label/alias registry, never private notes. Filters currently accept canonical slugs; alias lookup is reserved, not advertised |
| `PublishedCatalog`                   | Summary-only public selection view: legacy public rows or the explicitly selected published typed revision                           |

### Imported content: one authority, no fictional review

Backfill copies **identity only**. Existing `BestPractices` rows remain the single authoritative legacy body, with their existing v1 projection, HTML, Markdown, timestamps, and sources. v2 adapts them as `schemaVersion: 0`, `type: legacy-practice`, `revisionId: null`; family/product/outcome associations remain empty, applicability is null, maturity is unknown, evidence unreviewed, and fact-verification/review-due dates null. The summary is the first 500 SQLite characters of the description; detail preserves the full v1 body. This intentionally does not infer a rule type or classify every imported record as WAF.

Do not independently edit a shadow v2 body for a legacy record. A database gate rejects switching a legacy entry to a typed published pointer until an explicit authored v1 adapter and document parity are reviewed in a later implementation. New native typed entries are **not v1 eligible** and are not inserted into `BestPractices` as fake rule-shaped placeholders. Full existing HTML/Markdown/sitemap exports remain the legacy catalog. No actual native content is added to the production seed in Phase 2; the four typed examples are synthetic test fixtures, not published pilots.

### Numeric IDs and old-app recovery

The additive trigger registers subsequent legacy creations. Native reservations advance the legacy `sqlite_sequence` high-water mark; migration also carries deleted legacy-ID history into the catalog sequence. Thus either old-app legacy inserts or native identity allocation can continue without colliding or reusing deleted IDs. Trigger-scoped inserts preserve SQLite's outer `last_insert_rowid()`.

The v1 `create-practice:v1` operation namespace, normalized field ordering, hashes, original insertion SQL, transactional receipt batch, transient retries, replay/conflict behavior and cache-owning purge dispatch are unchanged. Both initial/replayed writes still purge the `practices` tag. Private receipts and high-water counters belong in full private backups, never public seeds.

### Native typed bodies

`src/content/types.ts` and `validation.ts` define exact schema-version-1 envelopes. Shared fields include title/summary, primary and multiple families, products/outcomes, applicability requirements/exclusions/dependencies, ordered sources, independent evidence/maturity and editorial/fact-verification/review dates.

- Recommendation: rationale, bounded prose/warning/code blocks, validation.
- Rule/policy: product, phase, scope, conditions, availability caveats, expression, separate action, rollout, rollback and validation.
- Reference architecture: assumptions, components, flows/trust boundaries, routing/DNS, identity policy, failure modes, trade-offs, text diagram, validation and rollback.
- Implementation guide: prerequisites, ordered steps, file/language/purpose code artifacts, validation and rollback.

Unknown types/versions/keys, arbitrary nested objects and active HTML/MDX/SVG block types are rejected. Text remains inert data, not rendered HTML. Arrays/strings/sources have explicit limits; the complete validated UTF-8 envelope is at most 64 KiB. Future command routes must additionally use the existing streamed byte-bounded parser **before** validation. Pure validators do not replace streaming limits. Product entitlement and factual correctness still require human/public-source review; a valid schema is not deployment evidence.

A publication freezes the body and relationships, including against SQLite `INSERT OR REPLACE`. At least a primary-family association, product and source must exist before a publication record. Unselected revisions remain private. Database constraints enforce relational invariants, not every TypeScript body rule: direct SQL must be validated by the release checks. Invalid stored native detail fails closed with 500/no-store, not raw unvalidated JSON. Publication authorization, conflict/idempotency commands, reviewed fact dates and previews are Phase 4 work.

## Read contracts

The implemented routes are documented in [OpenAPI v2](../../public/openapi-v2.json), linked from the existing schema, API catalogs, HTML/Markdown API docs, auth guidance, llms resources, agent skill/index and additive read-only WebMCP tool. The old WebMCP tool/contract is retained.

| Route                  | Response                                                                                                                    |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `/api/v2/entries`      | Published summaries, count/total/page/pageSize/pages/effective query and relative pagination links; no body/source download |
| `/api/v2/entries/{id}` | One complete published JSON detail in `{success, data}`; unknown/unpublished ID returns 404/no-store                        |
| `/api/v2/facets`       | Populated type/family/product/outcome counts, with every effective filter applied together                                  |

`q` is a literal title/summary substring, ASCII case-insensitive, bounded to 200 Unicode code points; `%`, `_`, backslashes and SQL syntax are ordinary text. It is not full-body search or relevance ranking. AND filters use canonical family/product/outcome slugs and an allowlisted type. Default/irrelevant parameters are removed, first duplicate wins, malformed filters are ignored, and unknown valid slugs match no entries. Shared normalization runs before Workers Cache and SQL; detail drops all queries, so `draft`/`preview` flags cannot affect visibility.

Page size defaults to 20 and clamps to 50; page defaults to 1 and clamps to 10000. Empty/out-of-range pages retain accurate totals. `pages` is the mathematical total; `next` stops at page 10000 rather than looping after normalization. Sort is title/ASCII NOCASE ascending or recorded modification date descending, always with numeric ID ascending as tie-breaker. Listings/counts and facets run in D1 batches. Offset pagination is not a stable cross-request snapshot under concurrent writes; refine filters for very large result sets. Native canonical paths remain null until HTML/Markdown support actually exists; JSON `detailPath` is usable now.

### Search evaluation

Current [D1 documentation](https://developers.cloudflare.com/d1/sql-api/sql-statements/#supported-sqlite-extensions) supports FTS5, confirmed in a local workerd test. FTS5 token/relevance behavior differs from literal substring matching (including partial tokens). At the 119-record baseline this slice deliberately uses bound `instr(lower(...), lower(?))` over published title/summary, avoiding D1's [50-byte LIKE-pattern limit](https://developers.cloudflare.com/d1/platform/limits/). No extra search service, duplicated draft-sensitive index, or relevance promise is introduced. Revisit FTS5/index maintenance after measuring an expanded catalog; no performance certification is claimed.

The existing **v1** long-search defect is separately characterized and **not corrected here**. Existing v1 query and error behavior remain unchanged; do not mistake v2's safe search for a v1 fix.

### Cache and access

All new reads use the explicit read registry/resolver and the existing uncached gateway -> `PublicReads.fetch()` path. Rate limiting remains before cache lookup; sessions start `first-primary`; every v2 response including facets shares the `practices` tag and existing 60-second browser/one-hour edge plus stale window. All dynamic reads retain GET/HEAD/OPTIONS, CORS, API noindex and no-store errors. No cookie/personalized state, public draft query, new write route, binding, Worker-first widening, account setting or Access-policy change is added. Schema files remain asset-first with static CORS/content-type headers.

Local workerd and mocked ownership tests do not prove real Workers Cache hits/purges, replica behavior, live Access policy or browser interoperability.

## Public seed and editorial release

`data/catalog-taxonomy.sql` adds only public editorial family/outcome labels, not classification or guidance. The active patch list is synchronized in `scripts/verify-content.py`, `package.json`, `create_d1_schema.sh`, the test seed loader and README release guidance. The production-derived `initial_data.sql` is deliberately unchanged.

`npm run db:seed:refresh -- /private/path/export.sql [output.sql]` now sanitizes an **existing approved full SQL export outside the repository**; it performs no remote operation. It exports legacy public tables and only current native published revisions, sources, associations and used taxonomy, rebuilding entries before pointers. It excludes private drafts/receipts, unpublished/older revisions, draft-only reservations and private high-water counters. It verifies the output loads under the migration schema before touching the destination. A pre-Phase-2 export is rejected rather than silently dropping native content. Never use a public seed as a full backup.

`content:check` verifies the seed and every active patch twice including timestamps/sequences, model relationships and private exclusions, plus four Python upgrade/export self-tests. A workerd test also loads the actual seed/patches and retrieves every public detail through the production validator boundary; Python integrity checks are not a second competing body schema.

## Release gates and exact next action

1. Local checks passed: **168/168 workerd**, **6/6 boundary + 2/2 discovery**, **4/4 Python upgrade/export** tests, integrity/repeat-run patches, isolated Wrangler local migration/seed, strict types/typegen/deploy dry run, and isolated Astro proof **12/12** check/build/dry run. See the roadmap for evidence and limits.
2. Independently review `0006` (circular composite FKs, immutable triggers and shared ID sequences), legacy-adapter design, query contracts and export sanitizer.
3. Obtain a fresh approved **private production export**, including existing receipts/sequences. Rehearse migration and twice-run taxonomy patch on an isolated local copy; test pre-upgrade app writes/receipt recovery and old-app rollback there. The checked-in public seed plus synthetic receipts is **not** a current production copy.
4. Only with separate owner approval: take a private recovery bookmark; apply migration before application/schema-dependent code and approved taxonomy data; deploy and verify live variants, new endpoints, write/replay purges and Access. CI remains credential-free and never runs remote operations.
5. Native pilot authoring/HTML+Markdown belongs to Phase 3; no real native publication until its end-to-end gate. Rich editorial write/publication commands and roles belong to Phase 4. Legacy conversion stays blocked until compatibility adapters are reviewed.

No remote rehearsal, staging/live checks, production rollout, performance/accessibility certification, commits or pushes are claimed by this local implementation.
