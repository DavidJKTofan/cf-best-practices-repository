# Phase 4: safe editorial authoring

> Historical local milestone below. The [initial scoped release](../rollout-2026-10-31.md) subsequently applied 0006–0007 and deployed these handlers after private-copy rehearsal; no live roles or native publications were provisioned. Dependency hardening/anonymous reads have later evidence, not independent acceptance. See [current v1.1 status](../rollout-2026-10-31-v1.1.md) and [operational gates](../phase6/operational-acceptance.md) for the remaining review, staging, recovery and authenticated mutation/purge work.

**Status:** implemented and verified locally on 2026-10-30; not staged or deployed. Owner directed Phase 4 development after local Phases 0–3. No commit, push, remote data write, live role grant, deployment, or Access/security-policy change is authorized. The [roadmap](../cloudflare-platform-roadmap.md) is the resume checkpoint. Earlier independent review, dependency audit, current private production-copy rehearsal and live-cache/Access gates remain open.

## Boundaries and implementation

- `migrations/0007_editorial_workflow.sql` is additive to `0006`; no applied migration or legacy creation SQL/hash/receipt is changed. It adds private role grants, draft workflow/contributors, immutable review records, durable mutation receipts, and public revision-scoped lifecycle JSON. Existing revisions default to active; publication freezes that column with the existing whole-row triggers.
- `src/api/catalog-editorial.ts` is a thin protected adapter. `src/modules/editorial/` separates authorization, command validation, queries, mutation orchestration/transaction construction, and previews. Shared content/lifecycle validation and typed presentation remain in `src/content/`.
- `/dashboard/editorial` is an asset-first workbench with type-specific JSON scaffolds, a paged working-copy queue, version/status, saved-copy HTML/Markdown previews, and save/submit/approve/request-changes/publish actions. It uses DOM APIs/textContent, not API-data innerHTML. No new hydrated framework or binding is introduced.
- Drafts must be complete schema-valid envelopes, not arbitrary partially valid JSON. Scaffolds are placeholders, not publishable recommendations. Human review must replace placeholders, establish public sources, check applicability/entitlements and validate examples. Product slugs must already exist in the reviewed registry; this phase intentionally adds no taxonomy-write API or production product/content seed.
- All private reads/writes stay under `/dashboard/api/catalog…` and bypass `PublicReads`. Existing scoped Worker-first paths already cover them; CSS/JS and the static dashboard shell remain asset-first. Private responses are no-store/noindex with no public CORS or cache tag. Previews have a script-free CSP and a PRIVATE PREVIEW banner. Public flags can never select a draft.

## Authorization: login is not a role

The Worker first verifies the existing Access JWT (issuer, audience, algorithm, expiry and stable user/service identity). It hashes the resulting stable subject using SHA-256 and looks up explicit `EditorialRoles(actor_hash, role)` grants from a `first-primary` session. Email addresses, caller role headers and arbitrary signed JWT role claims are not authorization. Neither valid login nor `ALLOW_LOCAL_WRITES` automatically grants editorial roles.

| Role               | Capabilities                                                                                    | Additional constraints                                                                       |
| ------------------ | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Any editorial role | Private paged queue, validated saved draft, HTML/Markdown preview, publication-history metadata | No public query flag or anonymous preview                                                    |
| Editor             | Reserve native ID, save draft, submit, explicit rebase                                          | Exact optimistic version; no legacy conversion                                               |
| Reviewer           | Approve saved in-review version or request changes                                              | Must never have contributed to the entry                                                     |
| Publisher          | Publish approved saved version                                                                  | Must never have contributed; reviewer must still have reviewer grant; public base must match |

A reviewer may also be the publisher; the independent reviewer must differ from **all** recorded contributors. Contributors are conservatively retained for the entry's lifetime, not only its latest edit. This intentionally trades flexibility for simple auditable separation. Changing that policy needs a separately reviewed implementation, not deleting contributor rows ad hoc.

Grants are **private owner-managed data**, with no HTTP self-service provisioning endpoint. For a user, the stable subject is `JSON.stringify([configuredIssuer, 'user', verifiedSub])`; service identities use `'service'` and the verified signed `common_name`. Hash exactly that UTF-8 string. Local bypass identity is the literal `local-dev`, only when existing opt-in and loopback requirements both pass. Never commit real subjects, grants, private review/receipt exports or full backups. Before any live grant, independently verify the identity and intended capability, confirm owner approval, and follow the private-copy/backup/rehearsal process. Tests provision synthetic roles only in ephemeral databases.

New mutations recheck the actor's grant inside the transaction, and publication rechecks the approved reviewer's grant. Revocation denies subsequent private requests; an already committed publication is not automatically withdrawn by revocation. An authorized publisher can still replay that committed receipt to recover a lost purge.

## HTTP and state contracts

The [editorial OpenAPI](../../public/openapi-editorial.json) and [auth guidance](../../public/auth.md) describe the implemented interface. Existing public read OpenAPI/WebMCP/agent catalogs remain read-only; no autonomous publication tool is exposed.

Public HTML/Markdown API docs and the read skill explain lifecycle/replacement handling, stable retired citations and the distinction between active status and verified freshness/entitlement. Read docs link the separate protected schema with its local-only release status; the skill remains a public-read workflow and its discovery digest matches the final bytes.

| Route under `/dashboard/api/catalog` | Method   | Input / result                                                                           |
| ------------------------------------ | -------- | ---------------------------------------------------------------------------------------- |
| Root                                 | GET/HEAD | 20 summaries per `page` (1–10000), roles; empty page ends traversal                      |
| Root                                 | POST     | `{content, lifecycle}`; reserve native identity and version-1 private draft              |
| `/{id}/draft`                        | GET/HEAD | Validated content/lifecycle, version, workflow status, base public revision, update time |
| `/{id}/draft`                        | PUT      | `{expectedVersion, content, lifecycle}`; save next version, invalidate review            |
| `/{id}/preview`                      | GET/HEAD | Saved HTML; `?format=markdown` uses shared Markdown renderer                             |
| `/{id}/submit`                       | POST     | `{expectedVersion}`; draft → in-review                                                   |
| `/{id}/review`                       | POST     | `{expectedVersion, decision: 'approve' or 'request-changes'}`; approved or draft         |
| `/{id}/publish`                      | POST     | `{expectedVersion}`; freeze snapshot, select it publicly, mark working state published   |
| `/{id}/rebase`                       | POST     | `{expectedVersion, expectedPublishedRevisionId}`; explicit reconciled base, reset review |
| `/{id}/history`                      | GET/HEAD | Up to 50 publication metadata records; `nextBeforeRevisionId` cursor as `before`         |

Every successful mutation increments the draft version, including submit/review/publish/rebase. Creation starts at 1. Version 0 on save starts a draft for a native published entry without one. Editing a published working copy starts a new review cycle based on the current public pointer. Editing an unpublished branch preserves its base; an out-of-band publication change produces a 409 instead of silently overwriting it. Explicitly reconcile against the current public content, save, then acknowledge the exact current pointer with `rebase`; that resets approval and requires independent review again. Rebase is API-only, not an automatic workbench merge. History provides metadata, not an unrestricted old/private-revision body endpoint.

Mutations require exact `application/json`, a random 16–128-character `Idempotency-Key` and the existing streamed **64 KiB** UTF-8 parser. Actual bytes are counted; misleading/missing lengths, invalid UTF-8/JSON and unknown envelope fields fail closed. Cross-origin Origin or Sec-Fetch-Site rejects writes; no editorial CORS/preflight permission is offered. GET/HEAD never mutate. New routes accept only their documented methods. Existing legacy creation remains its separate unchanged contract.

## Publication, facts and lifecycle

Submitting/publishing revalidates the stored typed content. It requires non-unreviewed evidence, a recorded non-future fact-verification date, a non-future editorial modification date, and a review-due date after today. Evidence, product maturity and editorial freshness remain independent. A source link resolving or JSON validating is not human fact verification, lab evidence or account entitlement.

Publication's D1 batch atomically:

1. Inserts an actor/key-scoped durable receipt with a constraint-checked optimistic/workflow/authorization/base precondition.
2. Advances working version, creates a new revision with lifecycle, and writes its sources and taxonomy associations.
3. Adds its immutable publication record and switches the entry's published pointer.
4. Marks working state published and records the immutable result in the same receipt.

A failed FK, guard or later statement rolls back **all** statements. Receipt checks gate every SQL mutation. Fresh attempt nonces on every transient retry ensure a committed-but-lost response is replayed rather than rerunning writes. The same actor/key with changed command, target, expected version or normalized data returns 409. Failed validation/conflicts do not consume a new key. Receipts are retained; there is no cleanup/TTL that could allow duplicates. The existing v1 operation-key namespace and receipts are unaffected.

Only publication affects public content. Initial publication and authorized replays attempt `ctx.exports.PublicReads.purgePractices()` from the cache-owning entrypoint. Public listings, facets, families, HTML/Markdown/JSON, sitemap and full exports share `practices`; taxonomy registry writes are not part of this API. A purge failure does not undo a committed publication. A replay recovers the purge attempt; local RPC success does **not** prove real edge invalidation, and purging cannot remove fresh browser responses.

Lifecycle is a public immutable revision field: `{state, reason, supersededBy}`. Active requires null reason/replacement; deprecated requires a public reason; superseded additionally requires another currently published **active** entry, not self or a private draft. This avoids supersession cycles in the supported command workflow. Changing status requires the same saved-version/review/publish cycle. Retired guidance retains its stable citation, status in HTML/Markdown/JSON summaries/details, and replacement link where applicable. No deletion, native-to-v1 coercion, legacy pointer conversion, automatic unpublication or third-party source fetching is added.

## Privacy, exports and browser recovery

`PublishedCatalog` remains the sole public selection boundary. New columns do not make drafts, unselected revisions, reviewer hashes or working-copy metadata public. The snapshot sanitizer now allowlists the lifecycle column but excludes all five `Editorial*` tables, drafts, legacy receipts, private revisions/reservations/counters. Snapshot integrity checks reject any private workflow table rows. A current-schema private export is required; old exports missing lifecycle must be locally upgraded/rehearsed, not silently stripped. Full private recovery backups must retain roles, reviews, contributors, receipts and allocator state. Public seeds are not rollback backups.

The workbench keeps private content in memory only. It stores an uncertain mutation's random key and payload SHA-256 signature in tab session storage, never tokens or content. Unchanged in-page retries keep the key. If storage is unavailable, reload loses recovery; even with storage, reconstructing the exact original command/body/expected version after reload is the operator's responsibility. A newly loaded latest version is **not** the uncertain prior operation. The workbench warns before discarding dirty text, disables workflow actions with unsaved edits, never overwrites a 409 automatically, and requires explicit publication confirmation. This is a validated JSON authoring desk, not a rich-text CMS, offline editor or automatic merge system.

## Evidence and release gates

- **198/198 workerd tests** pass, including 18 new editorial tests: all supported types, JWT plus private grants, local bypass denial, form/origin/key/bytes/UTF-8 validation, no-store previews, independence, revoked grants, every core transition and replay, concurrent creation/publication, actor scope, version races, lost commit recovery, FK rollback, stale-base/rebase recovery, fact dates, legacy conversion rejection, lifecycle and public exclusion.
- Strict types, **7/7 import/artifact boundary** and **2/2 discovery schema** checks pass. Latest Workers D1 types and public batch/session/cache-purge documentation were checked; no binding/config/typegen changes are needed.
- **5/5 Python upgrade/export** checks pass, including migration of already-frozen native snapshots, old-app insertion compatibility, lifecycle round-trip and new private role/review/contributor/receipt exclusions. The 119-practice seed and all three active content patches remain unchanged and pass repeat-run checks.
- Astro check: **0 errors/warnings/hints**. Build and **17/17 frontend checks** pass: built-Worker/artifact/displayed-example tests plus client retry-metadata tests. They include a real signed-author/reviewer/publisher journey, actual `ctx.exports` purge dispatch, public exclusion before publication, immutable revision selection, HTML/Markdown/JSON retirement parity, and explicit confirmation before changing an uncertain mutation key. Generated types and generated-configuration deployment **dry run** pass.
- Targeted Chrome checks: named form controls/visible keyboard focus; 320 px light/dark layout without document overflow; private draft save/preview links; disabled review/publication for an editor; simulated lost creation response retried to one version-1 draft; confirmed save plus refresh failure retained its returned ID, and the next save edited that entry rather than duplicating it. Session storage contained only key/signature; public detail remained 404 for the draft. The disposable preview and synthetic grants never touched ordinary local/remote data. These are not a full accessibility, browser, performance or independent security certification.

**Not verified/authorized:** current private production-copy receipts/sequences/upgrade/old-app rollback rehearsal; real edge-cache/purge/replica behavior; live Access path coverage and role administration; staging/production rollout or real native publication. Existing v1 long-search defect and previously recorded dependency audit findings are unchanged. Independent review should focus on transaction guards/attempt nonces, private role grants/contributors, review/version/base transitions, published lifecycle and sanitizer compatibility. Do not deploy until the separate release gates are satisfied.

## Public references checked

- [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/)
- [D1 transactional batches and sessions](https://developers.cloudflare.com/d1/worker-api/d1-database/)
- [D1 retry guidance](https://developers.cloudflare.com/d1/best-practices/retry-queries/)
- [Access JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Workers Cache purge ownership](https://developers.cloudflare.com/workers/cache/purge/)
