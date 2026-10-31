# Cloudflare catalog expansion: plan and roadmap

## Status and current checkpoint

- Last updated: **2026-10-31**.
- Repository: `cf-best-practices-repository`.
- Planning baseline: `1aaacbc18455153e77f1114c2f420ebc10bea564` (`v0.8`).
- Active phase: **Phase 6 — Deployed-release reconciliation and operational acceptance**.
- Status: **Owner-requested documentation/probe release `2e9c50c` deployed and read-verified; the application baseline remains `53e1f32` (`v1.1`), including restored filters.** See [point-in-time source/build/version and read evidence](rollout-2026-10-31-v1.1.md). Evidence-only commits may advance deployment metadata without changing the application. The [initial owner-approved scoped release](rollout-2026-10-31.md) completed fresh private-copy rehearsal, migrations 0006–0007, ordinary patches and Astro deployment, accepting independent-review/staging limits. Public counts remain 119 legacy/published entries; zero native revisions/roles/drafts was last established by the initial private inspection, not re-inspected here. Independent review, staging, exact-artifact recovery, authenticated mutations/retries, purge propagation and operational sign-off remain open; scoped deployment approval does not complete those gates.
- Authoritative roadmap: this file, linked from `AGENTS.md`; supersedes the external planning copy.
- Deliverables: [direction/decisions](phase0/direction-and-compatibility.md), [contract inventory](phase0/contracts.md), [wireframes](phase0/wireframes.md), isolated `experiments/phase0-astro-hono/` proof, [Phase 1 module evidence](phase1/module-boundaries.md), [Phase 2 model/read API](phase2/model-and-read-api.md), [Phase 3 frontend/pilot evidence](phase3/frontend-and-pilots.md), [Phase 4 editorial contracts/evidence](phase4/editorial-workflow.md), [Phase 5 curated expansion/release gates](phase5/curated-expansion.md), [individual legacy audit](phase5/legacy-audit.md), [Phase 6 rehearsal/rollout runbook](phase6/rehearsal-and-rollout.md) and [operational acceptance checklist](phase6/operational-acceptance.md).
- Verification: current local follow-up passes **225 runtime + 37 frontend**, strict types/**7 boundary + 3 discovery**, content integrity/four patches twice/**5 + 5 Python**, **9 Python + 12 Node** release checks, generated types, clean Astro check/build, generated deploy dry run and zero-finding root audit. New feature-specific smoke passes **10/10 live groups with HITs**; baseline remains compatible with older deployments. The [v1.1 record](rollout-2026-10-31-v1.1.md) reconciles exact-commit CI and targeted live API/SSR/Markdown/discovery/viewport evidence. Earlier initial-release evidence remains historical: fresh private offline/local D1/workerd rehearsal, post-write data/allocator/integrity comparison, **9 smoke groups + 42 requests/11 groups + 20 viewport/theme combinations**, keyboard/live-filter/history/no-script checks and independent cache HITs. One live trace recorded LCP 151 ms, TTFB 44 ms, CLS 0.00—not load/field/accessibility certification. No authenticated mutation/purge or completed monitoring-window evidence.
- Recorded defect: v1 long-search 500 is **corrected, regression-tested and deployed**; a production 200-character search returns 200. The baseline inventory retains its historical finding. Same six fields, literal semantics, ASCII case folding and existing 200-code-unit bound; no cache-key/schema/write-contract change.
- Deployed UX follow-up: Category/Feature/Domain/Level/Impact/Difficulty controls, labeled Domain-color pills/legend and removable active filters shipped in `53e1f32`. **60** original local viewport/theme/script-mode combinations remain distinct from subsequent targeted production checks. Data was preserved; read-time legacy classification is not native taxonomy. [Contract and local/live verification](phase6/filter-restoration.md). The owner-requested smoke/documentation/recovery-criteria follow-up is committed/deployed; deployment-approval mechanism work remains deferred and unchanged.
- Next action: retain the completed release evidence; assign the recovery operator, release observer and independent reviewers and reconcile scope/limits acceptance. Independently review Phase 2–6 contracts/source claims and exact source/artifact/dependencies, including live filtering and optimizer-statistics preservation. Reconcile a matching deployed compatible recovery artifact; version IDs or v0.8 source built with current dependencies are not proof. Agree monitoring thresholds/windows and approve exact staging resources/Access design before their journeys. Authenticated/purge and native-publication gates remain separate. No D1, grant/publication, recovery or security change was performed in this deployment.
- No commit, push, deployment, remote database write, or account/security-policy change is authorized by this roadmap.
- Prior frontend-simplification verification: **28/28 built checks**, **213/213 runtime tests**, clean Astro check/build, strict types/import/discovery, offline content integrity and generated-config deploy dry run. Targeted Chrome matrix: **90 combinations**, light/dark at 320–3840px. Rebuilt Wrangler follow-up: **179 HTTP checks**, including all 119 legacy pages; Explorer captured **181 successful root invocations, zero failed spans/5xx/error logs**, with expected 4xx rejections. [Evidence and limits](phase6/frontend-simplification.md); no rollout approval implied.
- Pre-release follow-up (historical): **36 frontend + 213 runtime**, **7 boundary + 3 discovery**, **9 Python + 7 Node** release checks and **40 local runtime/recovery assertions** passed before release. The earlier Level 5/5 scanner and `/catalog`/v2 404 findings describe the old deployment, not current production. [Historical evidence](phase6/scalability-and-production-readiness.md) and [superseding rollout](rollout-2026-10-31.md).

### Documentation checklist

- [x] Inspect existing architecture, content model, frontend, tests, and safeguards.
- [x] Review public Workers, Astro, and Hono integration guidance.
- [x] Record phases, acceptance gates, decisions, and session-resume protocol.
- [x] Publish the roadmap in the repository and reference it from `AGENTS.md`.
- [x] Check documentation links/formatting and update checkpoint with verification evidence.

## 1. Goal, scope, and principles

Expand the Cloudflare L7 catalog into a **Cloudflare recommendations and implementation-patterns catalog**, covering Application Services, Cloudflare One / Zero Trust / SASE, Developer Platform, Network Services, and cross-platform operations.

Support expressions/policies, connectivity architectures, implementation patterns, runbooks, and trade-offs. Focus on Cloudflare offerings; discuss third-party components only for necessary integrations/prerequisites.

1. Preserve IDs, canonical links, representations, security controls, and durable write/retry guarantees.
2. Separate product taxonomy, desired outcomes, and content types.
3. Prefer shared domain services and components to duplicated apps per family.
4. Start modular; extract deployable services only for demonstrated operational benefits.
5. Keep guidance available without JavaScript and accessible to permitted retrieval agents.
6. Publish sourced, applicability-aware guidance, not universal entitlement claims.
7. Separate publication, evidence, maturity, and freshness.
8. Deliver independently verifiable stages, not a combined framework/schema/content rewrite.

Initial non-goals: a Worker/database per family, mandatory SPA/React/Vue, automatic customer-account configuration, AI chatbot/semantic-search dependency, external CMS/competing content authority, or publishing internal research/customer details.

## 2. Baseline and required adaptations

The v0.8 baseline is a TypeScript Worker + D1 + vanilla static assets, with server-rendered HTML/Markdown. The uncached gateway forwards public reads through cached `PublicReads`. Creation validates Access JWTs, bounds streamed JSON, and uses transactional idempotency receipts and purge attempts.

Phases 3–5 add Astro SSR, bounded catalog/family discovery, safe editorial workflow and curated implementation/recovery collections around those boundaries. The 2026-10-31 scoped release deployed these readers/handlers, but native collections and role grants remain local fixtures; see the evidence and release limits above.

The dated seed baseline is **119 practices, 19 categories, 31 features**. Existing features already include Access, Tunnel, Workers, and network services: classify records individually rather than treating everything as WAF.

| Area                               | Adaptation                                                             |
| ---------------------------------- | ---------------------------------------------------------------------- |
| L7 branding/metadata               | Cloudflare-wide positioning; preserve unofficial-project disclaimer    |
| Flat `practice-data.ts` projection | Shared metadata, relationships, versioned typed bodies                 |
| Rule-oriented validation/enums     | Shared and type-specific schemas; unchanged legacy canonicalization    |
| Single detail renderer             | Shared shell and content-type-specific presentations                   |
| Full-body catalog download         | Server-side summary search, bounded pagination, selective detail reads |
| Add-only dashboard                 | Protected drafts/previews, review/publish, revisions                   |
| Single source URL                  | Multiple public sources and explicit fact-verification metadata        |
| Document query stripping           | Retain effective query state on new filtered SSR listings              |
| Discovery resources                | Expand only when new interfaces actually ship                          |

Frameworks do not replace authentication, transaction semantics, validation, cache policy, or byte bounds.

## 3. Information architecture

Proposed editorial families (not an official organizational chart):

- **Application services:** WAF, API security, bots, caching, DNS, TLS, availability.
- **Cloudflare One:** Access, Gateway, device posture, private apps, Tunnel, Zero Trust/SASE connectivity.
- **Developer Platform:** Workers, D1, R2, Durable Objects, Queues, Workflows, AI development.
- **Network services:** Cloudflare WAN, Magic Transit, Network Interconnect, related connectivity.
- **Cross-platform operations:** governance, Terraform, automation, observability, deployment.

Stable slugs/IDs, editable labels, rename aliases, multiple product/family associations, one primary breadcrumb placement. Do not duplicate entries across families or launch empty hubs.

Independent types:

| Type                   | Required emphasis                                                            |
| ---------------------- | ---------------------------------------------------------------------------- |
| Recommendation         | What/why, applicability, exclusions, validation                              |
| Rule / policy example  | Product/phase/context, conditions, action, scope, rollout/rollback           |
| Reference architecture | Assumptions, components, traffic/trust boundaries, failure modes, trade-offs |
| Implementation guide   | Ordered steps, files/configuration, dependencies, verification               |
| Operational runbook    | Task/symptom, diagnostics, safe changes, recovery, success criteria          |

Type is not inferred from family. Pilot: existing Application Security rule, Cloudflare One connectivity architecture, Workers/D1 implementation pattern. Start with the minimum templates supported by real entries.

## 4. Content and data model

Shared metadata: stable ID/title/summary/canonical URL; primary placement; multiple products/capabilities/families; outcomes/scenarios/audience; applicability/exclusions/dependencies; contextual recommendation strength/impact/effort; product-specific plans/add-ons/scope/version/limitations; publication/revision/supersession; public sources and editorial/fact-verification/review-due dates; separate evidence and maturity.

Do not generalize Free/Pro/Business/Enterprise to every product or imply that “Mandatory” is universally applicable official policy.

Use relational taxonomy, sources, revision/publication and entry associations, plus **bounded, versioned, validated JSON** for ordered blocks/type-specific bodies. Blocks may include prose, code artifacts (language/file/context/purpose/prerequisites), warnings, steps, tables, and reviewed static diagram references with text equivalents.

Never execute stored MDX or trust arbitrary active HTML/SVG. Escape text/attributes/JSON-LD, validate HTTP(S) sources, and use safe Markdown fences. Bound strings, nesting, block counts, and total streamed bytes; retain the 64 KiB write limit unless separately reviewed.

- D1 remains runtime authority; use additive migrations and schema-version discriminators.
- One authoritative body per revision; legacy representations are adapters, not independently edited copies.
- Retain legacy fields through compatibility/rollback windows.
- Explicit v1 eligibility: do not coerce architectures into rule-shaped v1 data.
- Preserve v1 hashing, operation-key namespace, normalized payload ordering, and durable receipts across upgrades.
- Content patches remain re-runnable SQL in `data/`; synchronize verifier, local seeding, and editorial release guidance.

Exact SQL and publication transactions are Phase 2 work; Phase 0 records proposed contracts/schema examples, not an applied migration.

## 5. Frontend and UX

An **engineering field guide**, not a marketing dashboard: readable code/prose/diagrams, restrained family accents, accessible contrast, light/dark, progressive disclosure.

Entry points: product family, desired outcome, global search, and compact “Browse all”. Hubs provide orientation and populated starting collections. Results share components but preview type-specific details: rule phase/action, architecture scenario/topology, developer services/runtime, runbook task.

Use ordinary URL-based forms/navigation, active-filter summaries, relevant facets, stable sort, bounded pagination, mobile filters, and selective detail loading. JavaScript enhances rather than enables core reading/discovery.

Shared reading shell: breadcrumbs, applicability, sources/freshness, related guidance, Markdown link, disclaimer. Rules separate expression from action/rollout; architectures foreground traffic/trust/routing/DNS/failure; developer patterns use file-oriented examples/bindings/retries/tests/observability/cost; runbooks foreground diagnosis/recovery. Essential content and diagram explanations appear in initial HTML and Markdown.

## 6. Framework and module architecture

Proposed: **Astro + Hono + TypeScript + Workers Static Assets + D1**.

- Astro: layouts, SSR pages, small enhancements; no extra UI framework required.
- Hono: route groups, HTTP middleware, API responses.
- Domain services: business rules/orchestration; repository/query modules: SQL.
- Render D1-backed pages on demand; credential-free builds must not need production D1.
- Disable unused framework sessions/image bindings; no incidental resource provisioning.
- Pin and test a compatible custom-entrypoint toolchain. Astro-only endpoints remain the fallback if Hono adds insufficient value.

```text
Static assets -> asset-first CSS/JS/images/reviewed diagrams
Uncached gateway
  -> PublicReads.fetch() [Workers Cache]
       -> JSON / Astro HTML / Markdown / discovery
            -> published catalog services -> D1 first-primary
  -> protected editorial commands
       -> Access + authorization + bounded validation
       -> transactional D1 writes + receipts -> PublicReads purge RPC
```

Target modules (create only as needed): thin `src/index.ts`; `entrypoints/public-reads.ts`; `api/{public,editorial,legacy}`; `modules/{catalog,taxonomy,search,editorial,discovery}`; `content/{blocks,types,registry.ts}`; `components/{catalog,content,diagrams,ui}`; `layouts`; `pages`; `platform/{access,cache,d1,http,observability}`. Keep schema/service/query/tests near their feature; enforce browser/server imports; avoid generic utility dumping grounds.

**Microservices:** initially one deployable Worker with explicit services, not one per product. Later candidates: source checks, imports, search-index generation, independently owned editorial automation. Extract only for ownership/security/workload/release isolation. Use service bindings, suitable Queues/Workflows, versioned contracts, and clear catalog write ownership.

## 7. API, caching, discovery, and security contracts

- Preserve `/practices/{id}`, `.md` aliases, `/#practice-{id}`, public v1 API and protected creation. Richer reads may use `/api/v2/`.
- All writes remain `/dashboard/api/*`; editor/publisher roles require explicit authorization beyond valid login. Protect dashboard/private previews.
- Default entrypoint cache stays disabled; keep scoped `run_worker_first` and free asset-first files.
- D1 public representations use `PublicReads.fetch()` (custom data RPC bypasses cache), `first-primary`, shared `practices` tag, and write/replay purge attempts from the cache-owning entrypoint. Invalidate taxonomy and all new derived representations correctly.
- Normalize Accept, preserve `Vary: Accept`, explicit Markdown aliases, and HEAD behavior.
- Existing documents strip UI queries. New filtered SSR listings retain canonical effective search/filter/sort/page state; remove irrelevant tracking, not meaningful state.
- Never shared-cache drafts, private previews, personalized state, auth failures, or cookies. Test adapter finalization so defaults cannot overwrite established headers.
- Local dev does not emulate Workers Cache. Edge hit/purge behavior requires a separately approved deployment.
- Search uses parameterized bounded D1 queries, stable order, summaries, facets, and sort allowlists. Evaluate supported full-text options/relevance before another service.
- Update OpenAPI, API docs, sitemap, llms resources, Markdown, auth metadata, catalogs, WebMCP, and agent skill/index as features ship; recompute skill digest. Bound/stream/partition growing exports without silent compatibility truncation.
- Preserve `search=yes, ai-input=yes, ai-train=no`, public indexability, anonymous reads, dashboard/404/API noindex, and owner-approved crawler/security policy. No incidental account/zone changes.

## 8. Editorial lifecycle and public/private separation

Draft -> review -> publish -> revise -> deprecate/supersede. Published revisions are separate from working drafts. Every public query/export/index/discovery path selects published content only. Protected non-cacheable preview routes use shared validated renderers; no public query flag may expose drafts.

Separate product maturity (GA/beta/EA/announcement-only), evidence (public-doc verification/lab testing/qualified evidence), and editorial freshness (modified/fact-verified/review due). Link success is not factual verification. Verify current sources/applicability before publishing new families.

Authorized background research was reviewed during Phase 0. No internal URLs, titles, excerpts, identities, or operational details belong in this public repository. Publishable claims must be independently established against public sources. Keep drafts, private reviewers, receipts, telemetry, full backups, and recovery bookmarks out of public seeds/repository.

Retain existing README unofficial-project, AS IS/no-warranty, liability, trademark, license, and copyright notices.

## 9. Phases and exit gates

Check only evidenced work; recommendations are not completed implementation.

### Phase 0 — Direction, contracts, compatibility proof

- [x] Owner directed continuation to Phase 1 on 2026-10-30; use proposed taxonomy/types/pilots/wireframes as working direction, not final publication or rollout approval.
- [x] Record framework, body/revision, v1 eligibility, and service-boundary proposals in the Phase 0 review; owner authorized the next structural phase.
- [x] Inventory HTTP/cache/auth/idempotency/discovery contracts and coverage in `docs/phase0/contracts.md`.
- [x] Prepare six low-fidelity wireframes in `docs/phase0/wireframes.md`.
- [x] Build isolated Astro/Hono proof around an existing public entry/protected creation in `experiments/phase0-astro-hono/`.
- [x] Verify named exports, real `ctx.exports`, purge dispatch, SSR/Markdown/JSON, signed-JWT Access checks, byte bounds, server source maps and asset output with 12 built-Worker/artifact tests. Actual cache effects remain unverified locally.
- [x] Review authorized background research; use public documentation for publishable pilot claims, with qualification rather than deployment claims.

**Gate:** tested integration plus representative schemas/wireframes; no broad replacement before passing. Separate local proof, owner review, and live-cache checks.

### Phase 1 — Behavior-preserving module boundaries

- [x] Extract gateway/read entrypoints, catalog/taxonomy queries, durable persistence and cache policy; retain already-separated Access, validation, bounded parsing and HTTP modules without cosmetic relocation.
- [x] Introduce thin Hono public/legacy/editorial groups using the Phase 0-tested version; preserve raw requests, path/method/error semantics and the asset fast path.
- [x] Enforce server/browser imports and public-artifact boundaries through a self-tested CI guard; preserve generated Env types and typegen checks.
- [x] Preserve URLs, response contracts, receipts and content; pass runtime/types/content/typegen/dry-run checks locally. See [Phase 1 evidence](phase1/module-boundaries.md); live cache/Access behavior remains a separately approved gate.

**Gate:** independently reviewable structural changes with no intentional behavior change.

### Phase 2 — Additive model and versioned read API

- [x] New additive migration: taxonomy associations, versioned bodies, sources, revisions/publication; 0006–0007 applied in the initial scoped release (see [contracts](phase2/model-and-read-api.md) and [rollout](rollout-2026-10-31.md)).
- [x] Identity backfill and explicit schema-version-0 legacy adapter preserve IDs/authority/visibility without invented taxonomy or verification; native conversion stays gated.
- [x] Shared/type-specific validation, published-pointer-only queries, unchanged legacy projection; no automatic native-to-v1 coercion.
- [x] v2 paginated summaries/details/conjunctive facets and canonical query normalization; literal title/summary search avoids the D1 LIKE limit, without changing v1 search.
- [x] Preserve old creation SQL/hashes/receipts/recovery locally; shared ID high-water marks and upgrade/rollback insertion tests, existing replay/lost-commit/concurrency coverage remain passing.
- [x] Extend public snapshot sanitizer, seed loader and verifier; exclude drafts/receipts/unselected revisions/reservations. Production-derived seed is unchanged.
- [x] Validate empty/local DB and isolated production-copy rehearsal before remote writes.
  - Empty workerd/Python/seed checks and fresh approved private offline/actual local D1/workerd migration/patch rehearsal passed before the initial scoped release, retaining real receipts/private state and allocator floors. **40** local runtime/recovery assertions used recorded prior v0.8 source with current dependencies; exact deployed-artifact matching and independent compatibility acceptance remain open. See [private-copy evidence](phase6/scalability-and-production-readiness.md) and [fresh release rehearsal](rollout-2026-10-31.md).

**Gate:** old contracts survive; new representative entries round-trip without draft leaks.

### Phase 3 — Astro frontend and end-to-end pilot

- [x] Shared Astro shell/components/metadata/public-safe field-guide branding, populated hubs and URL-based bounded discovery; readers deployed, empty legacy taxonomy hubs omitted.
- [x] Rule/architecture/developer HTML+Markdown, sources/freshness and related-family guidance; readers deployed, native content verified in disposable fixtures only; no v1 coercion.
- [x] Three complete authored representative entries across Application Security, Cloudflare One, Workers/D1, confined to ephemeral fixtures; existing practice 18 and all legacy IDs preserved. No native production publication.
- [x] Targeted Chrome keyboard/mobile/no-script/light-dark/copy-success/failure/fragment/text-diagram checks and automated empty/missing/unavailable states. Not a complete WCAG/assistive-technology/cross-browser audit.
- [x] Published-revision/discovery/export parity and actual built-asset private/source-map inspection; Astro build/test/generated-config dry run integrated into credential-free CI.

**Gate:** all three journeys work end to end; existing links survive; browsing needs no full-body catalog download.

**Local gate passed; readers subsequently deployed:** [implementation and evidence](phase3/frontend-and-pilots.md), [initial release](rollout-2026-10-31.md) and [v1.1](rollout-2026-10-31-v1.1.md). Private-copy rehearsal and anonymous cache/read checks have evidence; independent review, exact-artifact recovery, staging/signed Access and native publication approval remain separate. This gate does not establish live editorial roles or publication.

### Phase 4 — Safe editorial authoring

- [x] Type-aware drafts/protected HTML+Markdown previews and deny-by-default editor/reviewer/publisher authorization (local).
- [x] Independent review, immutable publication/revisions, deprecation/supersession and fact-verification metadata (local).
- [x] Optimistic version/base conflicts and explicit rebase, actor-scoped durable receipts, transactional publication and cache-owning purge/replay dependencies (local).
- [x] Public exclusion tests across APIs/docs/search/families/sitemap/exports and sanitized seed; built signed-identity journeys and targeted browser recovery checks (local).

**Gate:** drafts cannot change public guidance until publication; publication updates representations safely.

**Local gate passed; handlers subsequently deployed:** [contracts and evidence](phase4/editorial-workflow.md) and [initial release](rollout-2026-10-31.md). Roles/reviews/receipts remain private. No production grants, native publications or Access-policy changes were performed; staging, signed production mutations/retries/purge, independent review and exact-artifact recovery remain open.

### Phase 5 — Curated expansion

- [x] Audit/classify all 119 old records individually; retain IDs/bodies/caveats. Audit is proposed placement, not public legacy conversion or renewed fact verification.
- [x] Useful Cloudflare One/Developer starter collections: two authored implementation/recovery pairs, populated only in disposable local snapshots; no broader empty hubs or pilot duplicates.
- [x] Guide/runbook variants backed by four real authored entries. Runbooks remain strict implementation-guide body variants; readers/clients must support the variant before publication and during rollback.
- [x] Verify product-specific plans/licensing, relevant configuration/runtime semantics, prerequisites/failures/rollback/public sources and separate fact dates. Evidence remains public-docs, not a live deployment/entitlement claim.
- [x] Twice-apply four active local patches plus opt-in generated starter snapshots; synchronize verifier/seeding/tests/release guidance. Normal seeds add labels only; native snapshots are excluded from ordinary/remote seeding.

**Gate:** useful populated journeys with current public evidence, not empty hubs or duplicates.

**Local content gate passed:** [implementation, evidence and publication limits](phase5/curated-expansion.md). Reader support/registry labels deployed in the initial release; authored content remains disposable. Independent content/security/compatibility review and staging/authenticated/purge/recovery gates remain open. No legacy conversion, native production publication or live role provision is implied.

### Phase 6 — Rehearsal and approved rollout

- [ ] Isolated staging/Access; never local DB `remote: true`.
  - [x] Opt-in private configuration, fail-closed target/cache/asset/resource isolation checks and separate `dist-staging/` build verified with synthetic targets; actual generated public artifacts checked and deployment dry-run passed. This is not provisioned staging or verified Access.
- [x] Rehearse migrations/repeat-run patches on private production copy including receipts.
  - [x] Offline/synthetic tooling and fresh approved private offline/actual local D1/workerd rehearsals preceded the initial release. Post-write private application data matched rehearsal with preserved allocator floors and clean integrity/FKs; no private refresh was performed for the code-only v1.1 recheck.
- [ ] Expand/contract and old-app rollback, publication/cache recovery.
  - [x] Synthetic SQL probes, retained private backup checks and 40 actual local cross-version/runtime/recovered-state assertions; compatible-reader/lifecycle/runbook recovery procedure documented. Prior source with current dependencies is not the exact deployed artifact. Exact-artifact rollback/actual Time Travel/live purge recovery remain unperformed; see [manifest requirements](phase6/operational-acceptance.md).
- [ ] Runtime/schema/negotiation/security/accessibility/browser tests.
  - [x] Full local runtime/build matrix and synthetic/built read-probe tests pass, including recorded-filter expectations and native classification isolation. Local absence of edge Access/cache is detected, never reported as success. Targeted live read/cache/browser checks pass; complete accessibility/cross-browser, signed mutation/purge and scale certification remain open.
- [x] Initial scoped release explicitly approved with accepted independent-review/staging limits; refreshed private backup/bookmarks before its D1 mutations. No general future approval.
- [ ] Reconcile observed v1.1 acceptance and actual operator/reviewer assignments; complete [operational observation/sign-off](phase6/operational-acceptance.md). Deployment-approval mechanism work is deferred, unchanged.
- [ ] Separate reversible releases; live HTML/Markdown variants/purges/public reads/Access/retries/discovery.
  - [x] Additive 0006–0007/ordinary patches and compatible Astro readers deployed separately from grants/publication; v1.1 anonymous HTML/Markdown/JSON/filter/discovery/HIT evidence reconciled. Reversal readiness and authenticated retry/purge gates remain open.
- [ ] Refresh public catalog-only seed after an approved public-snapshot change/export; no refresh occurred in the initial release or this follow-up. Code-only v1.1 requires no new data patch/seed refresh.
- [x] Public-safe historical and current rollout evidence/limitations recorded; private backups/bookmarks/telemetry stay outside the repository. Current source/build/version reconciliation is not exact recovery-artifact provenance.

**Gate:** live evidence and recovery readiness, not just build/dry run. CI remains credential-free with no deploy/remote writes.

**Scoped release deployed; complete live exit gate still open:** [Phase 6 tools/runbook](phase6/rehearsal-and-rollout.md), [v1.1 evidence](rollout-2026-10-31-v1.1.md) and [operational acceptance](phase6/operational-acceptance.md). Only evidenced subsets are checked above; future provisioning, private export, deployment, grants/publication, remote D1/security changes or seed refresh still need their specific approvals.

### Remaining local hardening after Phase 6 tooling

- [x] Correct the separately recorded v1 long-search 500 without shortening its normalized input, changing searchable fields or widening v1 visibility; add runtime and actual built-Worker regressions.
- [x] Remediate recorded tooling dependency advisories with current-major patched releases; clean-install, audit and reverify root, isolated proof and synthetic staging artifacts.

**Completed and subsequently deployed in the initial scoped release:** [changes/verification](phase6/development-hardening.md) and [rollout](rollout-2026-10-31.md). These do not close independent review, exact-artifact recovery or the remaining live Phase 6 gates.

### Optional later service extraction

- [ ] Measure candidate workloads; define ownership, versioned service-binding contracts, retries/idempotency/tracing before extraction. Not a prerequisite for expansion.

## 10. Verification and completion criteria

Keep existing runtime tests, strict types, offline twice-run content checks, generated binding checks, and deploy dry run. Add framework build/type/artifact checks, not replacements. Performance audits require web-perf + Chrome DevTools.

Regression matrix: old IDs/links/anchors/aliases; published-revision parity HTML/Markdown/JSON; GET/HEAD/OPTIONS/CORS/errors/rate limits/noindex; Accept q/exclusions/query keys/tags/purges; JWT signature/issuer/audience/expiry/service identity; streamed bytes/UTF-8/multibyte/missing or misleading lengths; lost commits/concurrent conflicts/rollback/retained receipts/replay purges; HTML/attribute/URL/JSON-LD/Markdown/diagram safety; published-only every read/export; keyboard/mobile/screen readers/no-JS; credential-free builds/CI; no server maps/private data in assets.

Success: a new family is mostly taxonomy/content work; a new type has explicit schema/rendering/editor/test extension points without unrelated feature changes.

## 11. Decisions and unresolved questions

| Item                                              | Position                                                                               | Gate                                              |
| ------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Modular architecture                              | Required                                                                               | Always                                            |
| Astro + Hono                                      | Deployed Astro/Hono readers/handlers; current source `53e1f32`                         | Independent review + remaining operational gates  |
| One Worker initially                              | Recommended; no per-family services                                                    | Owner review                                      |
| D1 authority / relational metadata + typed bodies | 0006–0007 applied/rehearsed; legacy authority retained until reviewed conversion       | Independent review + native publication gates     |
| v1 eligibility                                    | Existing IDs grandfathered; explicit legacy adapter; no native coercion                | Native conversion later gate                      |
| Full-text search                                  | FTS5 supported/tested; bounded literal summary search selected initially               | Measure before index adoption                     |
| Background research                               | Reviewed, not a public content source                                                  | Public verification                               |
| Cache behavior                                    | Invariants authoritative                                                               | Local + approved live checks                      |
| Name/taxonomy/navigation                          | Proposed, not final                                                                    | Owner review                                      |
| Editorial roles/workflow                          | Handlers deployed; no live grants/native publication established by last private check | Independent review + approved grants/publication  |
| Runbook representation                            | Strict implementation-guide body variant; no table rebuild or new summary type filter  | Variant-aware readers before publication/rollback |
| Starter publication                               | Four authored disposable snapshots; real IDs allocated by reviewed editorial workflow  | Independent review + Phase 6 approval             |

Never describe future routes/frameworks/roles as deployed. Update `AGENTS.md`'s production description only when implementation changes land.

## 12. Session resume and progress protocol

1. Read `AGENTS.md`, current checkpoint, decision table, latest progress, and linked evidence.
2. Inspect `git status --short`, diff, and commit; investigate unfamiliar work, never discard it.
3. Confirm active user scope/mode; this roadmap is not blanket authorization.
4. Load applicable Workers/Wrangler/frontend/performance skills and reverify relevant docs.
5. Choose earliest incomplete task with satisfied prerequisites; read actual code/tests.
6. State next small deliverable and verification gate; execute only within scope.

After milestones/before stopping: update evidenced checkboxes, active task/files/checks/limits/blockers/exact next action; append history. Separate local/staging/production. Record failed/unrun tests. Keep tokens/identities/internal references/security inventories/raw telemetry/recovery locations out. On failure record last-good state, redacted error, partial effects and safe resume; never blindly retry remote writes.

```markdown
### YYYY-MM-DD — Milestone

- Phase/task and status: planned / in progress / blocked / completed locally / staging / deployed with approval
- Changes/files:
- Decisions/rationale:
- Verification/results/coverage limits:
- Remote effects:
- Blockers/remaining work:
- Exact next action:
```

### Progress log

#### 2026-10-29 — Initial plan

- Recorded external roadmap at clean baseline `v0.8`; application unchanged.
- Proposed Astro/Hono, typed shared content, one modular Worker subject to Phase 0.
- Public documentation reviewed; no test rerun, commit, push, deploy, or remote mutation.
- Historical blocker: Plan mode prevented repository integration; background connector then unavailable. Both are resolved for Phase 0.

#### 2026-10-30 — Phase 0 started

- Published this roadmap, added `AGENTS.md` handoff reference; production code/config/data/dependencies untouched.
- Baseline runtime tests: **75 passed in 5 files**.
- Reviewed authorized background material; kept all private source details out of repository deliverables.
- Compatibility proof and direction/contract/wireframe evidence in progress; owner taxonomy/UX approval and live-cache behavior remain separate gates.
- Remote effects: none. Next: complete isolated local proof and update this checkpoint with results.

#### 2026-10-30 — Local Phase 0 evidence complete

- Status: completed locally, **awaiting owner direction review**, not deployed.
- Deliverables: `docs/phase0/contracts.md`, `direction-and-compatibility.md` and `wireframes.md`; isolated `experiments/phase0-astro-hono/` package/lockfile, SSR specimen, runtime and artifact checks; roadmap/`AGENTS.md` handoff. No production source, config, migrations, seed, root dependencies or CI changes.
- Decisions recorded: one modular Worker initially, Astro custom-entrypoint seam + thin Hono groups, D1 authority/typed revision proposal, explicit v1 eligibility preserving all existing IDs and receipt semantics, three cross-platform pilots. Owner acceptance is not inferred.
- Production verification: `npm test -- --run` (**75/75**, 5 files), `npm run typecheck`, `npm run content:check` (119 records and twice-run patch integrity), `npx wrangler types --check`, `npx wrangler deploy --dry-run` all passed.
- Prototype verification: isolated `npm ci` succeeds; `npm run verify` generates types, checks Astro (0 errors/warnings), builds, runs **12/12** built-Worker/artifact checks and performs a deploy **dry run**. Tests include signed JWT/JWKS fixtures and real loopback/purge RPC dispatch, not mock creation success. Relative documentation links and formatting checked.
- Resolved prototype setup failures: checker peer conflict -> isolated TypeScript 6 rather than force-installing 7; Node engine -> isolated Node 22.23.4; unsupported current compatibility date -> pinned workerd-supported 2026-10-19; ESM/SQL helper import and streaming/escaped-prose test harness issues corrected. No partial remote effects.
- Baseline defect found: long searches exceed D1's 50-byte LIKE-pattern limit. A direct D1 query and unchanged legacy API reproduce the error; one of the 12 tests characterizes its current 500/no-store response, **not** a successful search or desired future contract. Production fix remains separate.
- Limits: no actual Workers Cache hit/purge/replica behavior, live Access policy, browser/accessibility/performance certification, or full production frontend/discovery parity claimed. Prototype uses a three-entry homepage/noindex HTML and is never a deployment target.
- Remote effects: none; no commits, pushes, deployments, remote database writes, or account/security changes.
- Exact next action: owner reviews Phase 0 direction/wireframes and approves taxonomy/pilots/service boundaries; agree a separate long-search correction and a small Phase 1 behavior-preserving module extraction. Do not advance the production framework/schema or mark Phase 0 owner confirmation complete without that review.

#### 2026-10-30 — Phase 1 module extraction in verification

- Status: in progress locally. Owner instructed continuation to Phase 1; Phase 0 proposals are the working baseline, not deployment or publication approval.
- Changes: thin `src/index.ts` re-exports; `src/entrypoints/` gateway/read boundaries; `src/api/` public/legacy/editorial Hono groups; catalog/taxonomy queries and durable creation under `src/modules/`; shared cache/CORS/rate limiting under `src/platform/`. Existing Access, bounded body parsing, validation, HTTP helpers and renderers remain separate and retain their established paths/exports.
- Verification so far: baseline **75/75**; **34/34** added gateway/cache characterization tests passed before extraction; all **109/109** then passed after extraction. Strict Worker types, catalog integrity (119 practices, repeat-run checks), generated types and deploy dry run pass. Additional receipt/search and boundary tests still in verification.
- Resolved/in-progress check issue: TypeScript 7 no longer exposes the old compiler parser API; boundary guard switched to a pinned development-only Babel parser without changing the compiler/toolchain. Rerun this check before completion.
- Limits: unchanged long-search defect; no actual edge-cache invalidation or live Access evidence. Dependency audit reports eight existing development-tool vulnerabilities, none in production dependencies; no unrelated upgrades applied.
- Remote effects: none. No commits, pushes, deployment, remote data writes or account/security changes.
- Exact next action: finish all regression/import-boundary checks, rerun the isolated proof against the preserved module exports, review the diff and record final Phase 1 evidence.

#### 2026-10-30 — Phase 1 completed locally

- Status: completed locally, ready for independent structural review; **not staged or deployed**. Phase 2 not started.
- Changes/files: `src/index.ts` preserves exports; `src/entrypoints/{gateway,read-gateway,public-reads}.ts`; thin `src/api/` groups/request scope; catalog filters/queries/durable persistence and taxonomy queries under `src/modules/`; shared cache/CORS/rate limiting under `src/platform/`. `read-api.ts`, `practice-creation.ts` and `public-content.ts` delegate while preserving earlier module exports. Existing Access/validation/body/HTTP/retry/rendering modules retain their contracts. README, `AGENTS.md` and `docs/phase1/module-boundaries.md` describe current local implementation.
- Decisions/rationale: adopt only pinned Hono 4.13.14 routing, not Astro/schema/frontend changes. Request-scoped composition retains generated platform types without casting Hono's execution context. Raw path matching, a HEAD routing view, original static-asset fast path and gateway-owned errors avoid framework defaults changing contracts.
- Regression evidence: baseline **75/75**; **34/34** characterization checks passed against the pre-refactor gateway. Final **117/117 runtime tests in 6 files** pass, including all original tests, fixed pre-refactor receipt hashes/replay/conflict, first-primary API/document fills, cache-owning purge dispatch, limiter ordering/outage behavior, exact paths, methods/errors/HEAD/OPTIONS and unchanged ASCII/multibyte/escaped long-search failures. Existing signed-JWT, byte-bound, concurrency/lost-commit/rollback, escaping, negotiation and discovery tests remain green.
- Verification: root `npm ci`, `npm test -- --run`, `npm run typecheck` (strict generated-Env types, **6/6** Node boundary-guard self-tests and actual source/public-asset scan), `npm run content:check` (119 records and twice-run timestamp/sequence integrity), `npx wrangler types --check`, `npx wrangler deploy --dry-run`, formatting and `git diff --check` pass. Credential-free CI runs the guard through its existing typecheck step; no deployment step added.
- Proof regression: isolated Node 22.23.4 `npm run verify` again passes type generation, Astro check (0 errors/warnings/hints), build, **12/12 built-Worker/artifact tests**, and deploy dry run against the refactored root modules. The proof's source/config/dependencies were not changed.
- Resolved verification failures: the first boundary-guard attempt assumed TypeScript's removed parser API; pinned development-only Babel parser 7.29.12 replaces it without changing TypeScript 7. A root `npm ci` attempt timed out during esbuild installation; the subsequent complete `npm ci` succeeded. No remote/partial data effects.
- Scope/limits: no changes to `wrangler.jsonc`, generated binding file, migrations, data/seed, public frontend/discovery bytes, Access rules or receipt/hash semantics. Long-search defect remains explicitly characterized, not corrected. Local cache mocks/RPC dispatch do not prove edge invalidation, replica lag or live Access policy. No browser/performance certification claimed. `npm audit` reports **8 existing development-tool vulnerabilities (4 moderate/4 high)**; `npm audit --omit=dev` reports **0**. Unrelated upgrades remain separate.
- Remote effects: none; no commits, pushes, deployments, remote database writes or account/security-policy changes.
- Blockers/remaining work: no local Phase 1 gate failures. Independent review and approved live verification are still required before release; search correction and exact Phase 2 schema/publication/v2 contracts remain separate work.
- Exact next action: review the Phase 1 diff, agree a standalone long-search correction, then design/review Phase 2 additive migrations and versioned read contracts. Do not start remote migration/rehearsal writes or deploy the isolated proof without separate authorization.

#### 2026-10-30 — Phase 2 core completed locally

- Phase/task/status: owner directed Phase 2 continuation from locally completed Phases 0/1. Additive model/read implementation and local verification complete; **independent review and fresh private production-copy rehearsal remain open**, not staged/deployed.
- Changes/files: `migrations/0006_catalog_model.sql`; public label-only `data/catalog-taxonomy.sql`; exact typed envelopes/body validation under `src/content/`; v2 normalization/projections/summary-detail-facet queries under `src/modules/catalog/v2-*`; read registry/gateway/`PublicReads` integration. Publication, revision-scoped sources/taxonomy, private working drafts, immutable history and numeric-ID compatibility are additive. No production dependency, Wrangler binding/configuration or existing creation SQL/hash/receipt change.
- Compatibility decisions: identity-only backfill preserves the single legacy body authority through an explicit schema-version-0 adapter, unknown taxonomy/maturity/evidence rather than fictional facts, and unchanged v1/HTML/Markdown. Native schema-version-1 bodies are not automatically coerced into v1. Legacy pointer conversion is blocked pending authored compatibility/document adapters; native canonical paths stay null until Phase 3. No real native entries added to `initial_data.sql`, no new editorial route or role enabled.
- Versioned reads: `/api/v2/entries`, `/api/v2/entries/{id}`, `/api/v2/facets`; bounded offset summaries/selective details/conjunctive populated facets; stable sort/ID tie-breakers and shared pre-cache/SQL normalization. Bound literal title/summary `instr` avoids D1's LIKE-pattern limit; FTS5 support/tokenization evaluated locally, not adopted as an unmeasured relevance/index service. **v1 long-search defect remains unchanged** and separately characterized.
- Privacy/discovery/tooling: sanitizer `scripts/export-public-catalog.py` takes an approved existing private export, performs no remote operation, explicitly allowlists tables **and columns**, verifies reload before output, and excludes drafts/receipts/unselected revisions/reservations/private counters. Active seed/patch paths and editorial guidance synchronized. `scripts/catalog_integrity.py`, four upgrade/export self-tests, actual-seed workerd detail validation, OpenAPI reference and optional WebMCP checks extend credential-free CI via existing commands. Updated HTML/Markdown API docs, schemas/catalogs, auth/llms/agent metadata and skill digest; old read-only WebMCP tool retained alongside v2.
- Verification: **168/168 workerd tests in 8 files** (117 existing + 49 model/API + 2 real-seed tests), strict generated-Env types, **6/6 boundary + 2/2 discovery checks**, actual artifact scan, **4/4 Python upgrade/export tests**, 119-practice integrity and all three active SQL patches twice (timestamps/sequences included), generated types and deploy **dry run** pass. Latest migration/seed/twice-run patches also applied successfully to an isolated Wrangler **local** database (119/119 legacy published). Formatting, shell syntax and diff whitespace checks pass.
- Regression proof: isolated Node 22.23.4 Astro check/build (0 errors/warnings/hints), **12/12** built-Worker/artifact checks and deploy **dry run** pass again; prototype source/config/dependencies unchanged. Existing signed-JWT, bounded parsing, lost-commit/concurrency/rollback, fixed legacy receipt/replay/conflict, content escaping, negotiation and cache-owning purge dispatch remain passing.
- Resolved local findings: fixture association order/count expectations corrected, query truncation made idempotent at whitespace boundaries, page-limit next-link looping prevented, publication guards cover `INSERT OR REPLACE` **and** private-to-published-ID `UPDATE OR REPLACE`, sanitizer excludes future private columns and refuses full-backup overwrite. CLI smoke checks also confirm output reload, private-receipt exclusion and refusal of in-repository full-export inputs. Initial formatter invocation included unsupported extensionless/plain-text files; JSON catalog formatted explicitly and plain `.gitignore` excluded from formatter checks. No partial remote effects.
- Limits/blockers: no fresh production export, real receipt/sequence rehearsal or actual old-app rollback against a current private production copy; the seed/synthetic upgrade checks are not substitutes. No real edge cache/purge/replica or live Access policy verification, browser interoperability/performance/accessibility certification, native HTML/Markdown pilot or publication workflow claimed. Existing development-tool audit findings were not changed by unrelated upgrades.
- Remote effects: none. Existing uncommitted Phase 0/1 work preserved. No commits, pushes, deployments, production seed refresh, remote data writes, account/security-policy changes or existing local development database mutation; rehearsal storage was isolated and ephemeral.
- Exact next action: independently review [model/read contracts](phase2/model-and-read-api.md), migration/shared sequence triggers and sanitizer; obtain an approved fresh private production copy including receipts/sequences; locally rehearse upgrade/twice-run patches and old-app write/replay/rollback recovery. Keep the final Phase 2 checkbox open until that evidence exists. Obtain separate owner approval before any live change; do not advance native pilot publication or deploy the isolated proof.

#### 2026-10-30 — Phase 3 completed locally

- Phase/task/status: owner directed Phase 3 continuation after local Phases 0–2. Astro presentation and three cross-platform journeys are **completed and verified locally**, not staged/deployed. Native pilots remain fixtures; independent release review and fresh private production-copy rehearsal remain open.
- Changes/files: `astro.config.mjs`, `src/astro-worker.ts`, `src/entrypoints/astro-reads.ts`, post-adapter `src/platform/content-response.ts`; SSR pages/layout/catalog/reading components and field-guide CSS; catalog document-state/listing loader/streamed exports/discovery; shared typed section/Markdown mapping; native canonical projection. Updated package/lockfile/config/typegen/Vitest entrypoint, discovery/API/agent metadata and digest, Astro import guard, credential-free CI, README/`AGENTS.md` and [Phase 3 evidence](phase3/frontend-and-pilots.md).
- Pilot files: `test/fixtures/pilots.json` authors WAF observation, Access/Tunnel browser topology and Workers/D1 durable creation with current public sources, prerequisites/trust/failure/rollback and separate fact dates. `scripts/test/helpers/frontend-harness.mjs` publishes them only into an ephemeral local harness, alongside unpublished/draft canaries; `scripts/preview-frontend.mjs` offers an explicit disposable browser preview and optional script-blocked proxy. No production seed/content patch change or legacy conversion.
- Decisions/rationale: preserve gateway/rate-limit/write/receipt/purge logic and use a cached read subclass for Astro HTML only; no full-body homepage API fetch or hydrated UI framework. Ordinary URL forms work without JavaScript. Only catalog/family listings retain effective query state; existing documents keep query stripping. Native HTML/Markdown/JSON share published revision data; v1 remains legacy-only. Full exports and discovery iterate bounded published batches. Pin Phase 0-tested Astro/adapter/checker and TypeScript 6.0.3 for compatibility; CI uses Node 22.23.4.
- Verification: clean `npm ci`, **180/180 workerd tests in 9 files**, strict generated-Env types, **7/7 boundary + 2/2 discovery checks**, **4/4 Python upgrade/export tests** and 119-practice/twice-run patch integrity, generated types, Astro check **0 errors/warnings/hints**, Astro build, **12/12 built-frontend/artifact/displayed-example checks**, and generated-config deployment **dry run** pass. Format/diff checks and local documentation references verified. The isolated Phase 0 proof was not changed or rerun during Phase 3; its prior evidence remains historical.
- Coverage: all 119 legacy HTML detail URLs, preserved practice-18 expression/action caveats, native HTML/Markdown/JSON revision parity and v1 exclusion, GET/HEAD/OPTIONS/method guards, form/pagination/canonical state, empty-family 404 and invalid-body 503/no-store, hostile text/quoted attributes/JSON-LD/code, published-only APIs/hubs/sitemap/agent/full exports, client artifact privacy and server-only source maps. Displayed SQL/TypeScript typechecks and runs local same-key/conflict/actor/recovery/concurrency/rollback checks; application auth/byte-bound/purge regressions remain passing.
- Browser evidence: narrow 320 px homepage/catalog and 390 px code/topology containment, visible keyboard skip-link focus, native form search with page scripts blocked, CSS-only system light/dark, hidden no-script controls, successful and denied-clipboard copy fallback, persistent theme toggle, preserved old fragment opening its disclosure. Cold local unthrottled desktop trace: LCP **290 ms**, CLS **0.00**, TTFB **12 ms**, render-blocking estimated savings **0 ms**. Targeted Chrome observations only, not production vitals or complete accessibility/browser certification; raw artifacts kept outside repository.
- Resolved failures: empty-family status moved from component to page frontmatter before rendering; string-only XSS false positive replaced with DOM parsing/attribute checks; RPC expected-rejection assertions wrapped in async callbacks. Final source/discovery/CSS rebuilt and all checks rerun after formatting.
- Limits/blockers: Phase 2 private production-copy receipt/sequence/rollback rehearsal remains unperformed; no actual edge cache/purge/replica or live Access evidence, no native production publication/editorial authoring. Known v1 long-search failure unchanged. Audit reports **7 findings (4 moderate/3 high)**; production-only graph reports **3 (2 moderate/1 high)** via the adapter's Wrangler peer/tooling dependencies, not zero. No unrelated automatic dependency upgrades applied.
- Remote effects: none. No commits, pushes, deployments, remote database writes, ordinary local database mutations or account/security-policy changes; existing uncommitted Phase 0–2 work preserved. Temporary preview processes started for this work were stopped at handoff.
- Exact next action: independently review the Phase 3 adapter/header/cache/representation seam and public-source examples together with Phase 2 model/export invariants; separately remediate/reverify tooling dependencies; obtain an approved fresh private production copy and rehearse before requesting any live release. Start Phase 4 only on owner direction; do not infer native publication or deployment authorization.

#### 2026-10-30 — Phase 4 completed locally

- Phase/task/status: owner directed continuation after local Phases 0–3. Safe native authoring/review/publication is **completed and verified locally**, not staged/deployed. Earlier private production-copy rehearsal and independent release review remain open.
- Changes/files: additive `migrations/0007_editorial_workflow.sql`; `src/modules/editorial/{authorization,validation,queries,mutations,preview}.ts`; thin `src/api/catalog-editorial.ts` and gateway routing; shared lifecycle validation/projection/Markdown and Astro status notices. Static `/dashboard/editorial` workbench, type scaffolds, separately tested retry metadata helper and CSS; protected editorial OpenAPI/auth docs; public snapshot sanitizer/integrity checks; runtime/built-Worker/retry/upgrade-export tests; README/`AGENTS.md` and [Phase 4 contracts](phase4/editorial-workflow.md). No root dependency, binding, configuration, existing migration, legacy SQL/hash/receipt, production seed or active content patch changes during this phase.
- Decisions/rationale: private owner-managed grants keyed by verified stable actor hashes, never JWT role/email claims or automatic local bypass grants. All contributors are permanently excluded from review/publication; reviewer may also publish but must still hold reviewer grant. Every mutation increments version; edits/rebases invalidate approval; transaction guards compare public base and role state. Fresh per-attempt nonces and one actor/key namespace protect all commands, including lost commit responses. Native publication alone purges the shared public tag, including receipt replays. Legacy conversion remains blocked.
- Publication/privacy: full validated typed drafts and script-free protected previews use shared content/section/Markdown logic; no public draft flag or cache path. Publication freezes body/sources/taxonomy/lifecycle and switches the published pointer atomically. Deprecation/supersession retain stable citations; replacement must be another active published entry. Private workflow tables and receipts are excluded from public seed/export. Product registry writes and real native publications are not added.
- Discovery polish: HTML/Markdown read API docs and the public read skill explain retirement/replacement handling without treating active status as proof of freshness or entitlement. Read docs link the separately protected, not-yet-deployed editorial schema; public agent tools remain read-only. Recomputed the skill index digest after the final content edit.
- Verification/results: **198/198 workerd tests in 10 files**, strict types, **7/7 boundary + 2/2 discovery checks**, **5/5 Python upgrade/export tests**, 119-practice integrity and twice-run patches pass. Astro check **0 errors/warnings/hints**, build and **17/17 frontend checks** pass; generated types and generated-config deploy **dry run** pass. Existing tests remain green; public/runtime/artifact journeys exercise actual `ctx.exports`, not live edge-cache effects. Formatting/diff checks pass.
- Browser evidence: disposable signed-author proxy/ephemeral DB only; named controls, visible keyboard focus, 320 px light/dark containment, private save/preview links, editor-only disabled review/publication, lost creation response retried to one draft, confirmed-save/failed-refresh recovery retained the returned ID and edited rather than duplicated. Only key/signature persisted; public draft detail stayed 404. No new production performance or full browser/accessibility certification is claimed.
- Resolved local findings: initial test RPC fixture omitted `PublicReads.fetch` (fixed; public-exclusion checks now assert statuses); presentation fixture gained required lifecycle data; public search canary made unique and distinguished from query echo. Astro formatting required the existing external formatter plugin. Browser-only proxy initially passed a native Request to Wrangler's URL/init test interface (fixed outside repo). Self-review added explicit confirmation before rotating uncertain keys, immediate confirmed-ID retention before refresh, and a published-working-copy base check. No partial remote effects.
- Limits/blockers: current private production-copy upgrade/receipts/sequences/old-app rollback/editorial recovery rehearsal unperformed; real Workers Cache hit/purge/replica behavior and live Access coverage/role administration unverified. Known v1 long-search failure and previous dependency audit findings unchanged; no reinstall or audit rerun. Workbench is a schema-valid JSON desk, not rich text/offline editing or automatic merge; exact-body reload recovery remains operator-controlled.
- Remote effects: none. No commits, pushes, deployments, live role grants, remote database writes, ordinary dev database mutations or account/security-policy changes. Existing uncommitted Phases 0–3 work preserved; browser fixtures and proxy remain outside production and are stopped at handoff.
- Exact next action: independently review Phase 4 transaction/auth/privacy/export contracts together with Phase 2/3 seams; remediate dependency findings separately and obtain an approved fresh private production copy for recovery rehearsal before any live approval. Phase 5 curated expansion requires owner direction; do not infer rollout or native publication authorization.

#### 2026-10-30 — Phase 5 completed locally

- Phase/task/status: owner directed curated expansion after local Phases 0–4. Individual legacy audit, two authored starter collections and strict runbook variants are **completed and verified locally**, not staged/deployed/published to production. Phase 6 is not started or authorized.
- Changes/files: `docs/phase5/legacy-audit.md` audits all 119 existing records; `data/phase5/starters.json` authors four entries and `scripts/phase5-content.py` generates opt-in `local-starters.sql`. `data/phase5-products.sql` adds four public registry labels only, synchronized with verifier/local seeding/Vitest/frontend harness. Runbook schema/validation/presentation in `src/content/`, editorial template/workbench and v2 OpenAPI/read docs/agent skill/digest; curated summary selectors in `src/modules/catalog/starter-collections.ts`, listing/Markdown loaders, Astro collection markup and responsive CSS. Added Worker/Python/built-frontend/displayed-example tests, `preview:starters`, [Phase 5 evidence/release procedure](phase5/curated-expansion.md), README/`AGENTS.md` and checkpoint updates.
- Decisions/rationale: legacy bodies/IDs/v1 classification remain authoritative; the audit does not invent verification or silently bypass conversion gates. Four distinct new topics complement rather than reload Phase 3 pilots. Runbooks are explicitly discriminated implementation-guide bodies, avoiding a constrained-table rebuild but requiring variant-aware readers/clients before publication and during rollback. Exact reviewed-title/family selectors read only active published summaries, hide incomplete/ambiguous/retired pairs and avoid hard-coded production IDs. Rehearsal IDs 810001–810004 are never production reservations.
- Sources/examples: all four retain public-docs evidence, fact date 2026-10-30 and independent review-due/editorial fields; current public Access/Tunnel and Workers/D1 documentation checked through MCP, all 15 unique source URLs return 200. Account-specific seats/logging/quotas/retention and actual cloudflared version must be verified in staging. Displayed SQL/TypeScript typechecks and executes bounded published-summary pages/index/live-membership tests; displayed Tunnel YAML passes installed cloudflared's local ingress/host/catch-all checks. None proves live JWT/origin/failover/cache behavior.
- Verification/results: **210/210 workerd tests in 11 files**, strict generated-Env types, **7/7 boundary + 2/2 discovery checks**, four active patches twice, generated SQL parity, **5/5 existing upgrade/export + 5/5 Phase 5 Python tests**, Astro check **0 errors/warnings/hints**, build, **22/22 frontend checks**, generated types and generated-config deploy **dry run** pass. Coverage preserves all legacy detail links/bodies/v1/receipts and public/private publication boundaries; exercises strict runbook rejection, role/version-protected publication, curated ordering/selection, 123-snapshot sanitized export round-trip, collision/high-water refusal and unchanged repeat-run timestamps/sequences. No migration, binding, dependency or production-seed change in Phase 5.
- Browser evidence: disposable preview only; 320 px light/dark, CSP-blocked page scripts, both ordered family pairs and complete runbook recovery/rollback, native search to uncertain-write recovery, visible skip-link focus and contained horizontal code scrolling. Cold unthrottled desktop family trace: LCP **92 ms**, CLS **0.00**, TTFB **10 ms**, render-blocking estimated savings **0 ms**; seven successful listed requests, no full-body catalog fetch. Not production vitals or complete accessibility/cross-browser certification.
- Resolved local findings: curation fixture state needed published-pointer restoration; a global HTML ordering assertion read alphabetic JSON-LD before the curated links, fixed by comparing parsed collection anchors. No remote/partial-data effects. Previous v1 long-search defect and dependency audit findings unchanged; no reinstall/re-audit or unrelated upgrades during this phase.
- Remote effects: none. No commits, pushes, deployments, native production publications, live grants, remote database writes, ordinary local DB mutations or account/security-policy changes. Existing uncommitted Phases 0–4 work preserved. Disposable preview processes started for Phase 5 are stopped at handoff.
- Blockers/remaining work: no local Phase 5 test blocker. Independent content/security/compatibility review, fresh private production-copy receipts/sequences/old-app/variant-reader/editorial recovery rehearsal, staging/live cache/Access and publication approvals remain open. `local-starters.sql` must never be used remotely; publication must allocate real IDs through the reviewed editorial workflow.
- Exact next action: independent Phase 5 audit/source/runbook review alongside Phase 2–4 contracts; obtain owner direction for Phase 6 and an approved current private copy before rehearsal planning/execution. No live release or security change is authorized by this completion.

#### 2026-10-30 — Phase 6 local readiness tooling

- Phase/task/status: owner directed Phase 6 development after local Phases 0–5. Local readiness tooling is implemented/verified; **current private-copy, actual staging and live rollout remain open**, not deployed. No approved current private export/allocator capture was supplied.
- Changes/files: `scripts/release_rehearsal.py`, thin `scripts/rehearse-release.py` CLI and synthetic Python tests; `scripts/release/{staging,artifacts,smoke}.mjs`, Node/tooling and built-Worker probe tests. Opt-in private `CF_STAGING_CONFIG` in `astro.config.mjs`, separate ignored `dist-staging/`, shared public artifact inspection, npm commands and credential-free CI release-tool checks. Added [Phase 6 approvals/rehearsal/recovery runbook](phase6/rehearsal-and-rollout.md), README/`AGENTS.md` and roadmap handoff. No Worker runtime source, applied migration, ordinary source binding config, content/seed, receipt/hash SQL or dependency change in this phase.
- Rehearsal decisions: require external full SQL export, separate consistent allocator capture, explicit verified baseline and a NEW private directory; preserve original inputs/private table contents and deleted-ID floors. Fail closed on partial schema, ledger contradictions or missing/altered publication guards. Pending migrations and ordinary active patches only, no disposable starter SQL. SQL replay/rollback/native reservation and full private backup recovery run on disposable branches; sanitized export is checked in memory, never written to the seed. Private provenance/failure diagnostics stay outside the repository; no raw data printed. This does not prove freshness, current-production provenance, workerd import or actual old-app runtime.
- Staging/probe decisions: validate isolated Worker/D1/hostname/Access audience/limiter with no remote-dev bindings, automatic resources, unsafe fallback or broad cache/assets. Build into separate output; generated paths/public artifacts and dry-run packaging checked. Anonymous probes require an explicit HTTPS origin and use bounded/timed GET/HEAD/OPTIONS only, no credentials/cookies/redirect following/writes; optional expected revision and HIT checks do not claim purge or authorized role/retry coverage. No generic public purge endpoint, live grants or security bypass added.
- Verification: **210/210 runtime tests**, strict types, **7/7 boundary + 2/2 discovery checks**, four active patches twice/generated starter parity, existing **5/5 + 5/5 Python checks**, new **8/8 Python + 7/7 Node release-tool checks**, Astro **0 errors/warnings/hints**, normal build, **23/23 frontend checks**, generated types and generated-config deploy dry run pass. Separate synthetic-target staging build, generated isolation/public-artifact check and staging deploy dry run pass. The new built-probe test expects only the anonymous edge-denial/HIT checks to fail locally, so passing tests cannot mislabel missing local edge features as live evidence.
- Findings/resolution: baseline-6 test snapshot could not use the migration-0007 lifecycle-aware disposable generator; fixture now explicitly stores the same authored bodies under the older schema. Normalized Wrangler's empty/undefined trigger defaults and macOS realpath aliases required test/preflight normalization; production target collision checks cover hostname/UUID case and numeric limiter aliases. A final verification batch stopped after release checks because nested `npx` inherited its outer call option (npm EUSAGE); remaining checks were rerun through npm scripts/local Wrangler, not bypassed. Frontend/build verification uses Node 22.23.4 rather than the system's older 22.19.0; no global runtime changed. These were local tool/fixture issues with no remote effects. Re-audit is **not clean**: 7 findings (4 moderate/3 high), 3 (2 moderate/1 high) with production-only filtering, both exit 1. No automatic fix/upgrade/reinstall. Existing v1 long-search defect remains separate.
- Limits/blockers: no current private-copy rehearsal, old-Worker/variant-reader rollback against actual private data, Time Travel restore, account/Access coverage, authenticated live retries/publication/purge/replica verification, staging provisioning or new browser/accessibility/performance audit. Independent review and dependency remediation/approved disposition remain open. Synthetic backup tests and dry runs do not close these gates.
- Remote effects: none; documentation retrieval and package audit only. No customer/account/production-data read/export/probe, remote writes, grants, publications, deployment, security-policy changes, seed refresh, commit or push. Existing uncommitted Phases 0–5 work preserved; normal local development D1 storage untouched.
- Exact next action: independently review new tools/operational sequence alongside Phases 2–5; resolve dependency disposition and obtain an approved fresh full private export plus consistent allocator capture/baseline. Run the offline tool, then actual isolated local workerd/old-reader/editorial recovery. Approve specific staging resources/Access design before provisioning or deployment; retain live checkboxes and Phase 2 private-copy gate as open.

#### 2026-10-30 — Remaining local search/dependency hardening

- Phase/task/status: owner requested remaining relevant development after local Phases 0–6. Two recorded development blockers are **completed locally**, not staged/deployed; earlier approval/private-copy/live gates remain open.
- Changes/files: `src/modules/catalog/queries.ts` replaces escaped LIKE with separately bound per-field `instr(lower(…), lower(?))`; `test/index.spec.js` and `scripts/test/frontend-runtime.check.mjs` add full-length positive/negative, six-field, filter, normalization, legacy parity, HEAD/header regressions. Read OpenAPI/HTML/Markdown docs and the Phase 0 compatibility check now reflect successful long literal searches; normalizers/cache keys remain unchanged. Root package/lockfile updates only direct Wrangler/Vitest/plugin tooling; proof package/lockfile updates Wrangler. Generated types, README/`AGENTS.md`, baseline finding annotation, release runbook and [hardening evidence](phase6/development-hardening.md) synchronized. No migration, ordinary config, data/seed, write/receipt/hash or security-policy change.
- Decisions/rationale: keep existing 200 UTF-16-code-unit acceptance and six independent fields, ASCII-only case folding, literal wildcard characters, AND filters/order and v1 eligibility. No new search service/index, silent byte truncation, framework major or forced audit fix. Root/proof Wrangler 4.156.0, root plugin 1.4.11 and Vitest 4.1.12; pinned Astro/adapter/checker/TypeScript/Hono unchanged.
- Verification/results: new regressions first failed against the old query (3 expected 500 failures), then all **213/213 workerd tests** passed before and after dependency changes. Clean Node 22.23.4 installs in both packages; strict types, **7/7 boundary + 2/2 discovery**, four patches twice, starter parity, **5/5 + 5/5 Python** content/export checks, **8/8 Python + 7/7 Node** release checks, Astro **0 errors/warnings/hints**, normal build, **24/24 frontend checks**, regenerated types and generated-config dry run pass. Separate synthetic staging build/generated isolation/artifacts/dry run and isolated proof check/build/**12/12 tests**/dry run pass. Full and production-only audits in **both packages return 0 findings and exit 0**. No new browser/performance/assistive-technology or independent certification.
- Resolved setup issues: Volta initially selected older Node through its npm shim; final clean installs/matrix use explicit supported binaries. Python reference-fetch certificate validation failed; npm supplied the latest Workers type reference without disabling TLS. Wrangler's expected stale-type check passed after regenerating both outputs. No partial remote data effects.
- Remote effects: public documentation/package retrieval only. No live probe, private export/read, commit, push, deployment, remote D1 write, native publication, live grant, seed refresh or account/security change. Existing uncommitted Phases 0–6 work and ordinary local D1 state preserved.
- Blockers/exact next action: independent review including the new query/locks; approved current private export plus consistent allocator capture/baseline, then offline and actual isolated workerd/old-reader/variant/editorial recovery. Obtain exact staging/Access approval before provisioning/deploying. Keep Phase 2's private-copy and Phase 6's live checkboxes open; re-audit before release.

#### 2026-10-30 — Owner-requested local Wrangler/browser review

- Phase/task/status: local runtime review completed using built Astro output, Wrangler 4.156.0 and Chrome DevTools/Local Explorer; no new application defect confirmed. Not staging/deployment or independent release approval.
- Setup/data: loopback-only `wrangler dev --local`, generated `dist/server/wrangler.json`, fresh external disposable persistence and application writes disabled. Imported seven migrations/public seed/four active patches using Explorer's D1 API; then explicitly loaded the four opt-in starter fixtures there only. Final state: v1 119, published catalog 123, zero roles/drafts/creation receipts. Ordinary local D1 state untouched.
- Verification: **44 HTTP checks pass**, including previous long-search failures, negotiated representations, HEAD/OPTIONS and denied writes/previews. Browser consoles/networks clean on public homepage/catalog/family/runbook/detail/API-doc journeys; mobile search and 320/390 px light/dark containment checked. Search/pagination/complete guide work with scripts blocked. Local homepage trace: **LCP 116 ms, TTFB 11 ms, CLS 0.00**; no deployed-performance/assistive-technology certification.
- Telemetry/findings: **129 root invocations all `ok`, zero failed spans/5xx/error logs**, nine explained rejection warnings. Dashboard listing's 401 and no-script CSP console errors are expected. Corrected one nonexistent-route probe and one telemetry column name; no runtime source fix needed. See [full evidence and limitations](phase6/local-runtime-review.md); raw artifacts stay outside the repository.
- Changed files: new local-review evidence, this checkpoint/progress log and hardening cross-reference only. No commits/pushes, remote data/account/security changes, role grants, production publication or seed refresh. Temporary script-blocking proxy stopped; requested local Wrangler server left running at handoff.
- Blockers/exact next action: independent review, approved current private export plus consistent allocator capture/baseline, then offline and actual isolated workerd/old-reader/editorial recovery. Specific staging/Access approval remains necessary; local Cache/Access limitations leave live gates open.

#### 2026-10-30 — Owner-requested frontend simplification

- Status: completed locally, not deployed. Restore the earlier simple, clean reference style without reverting the catalog/model/editorial work.
- Changes/files: `src/styles/field-guide.css`, shared layout and catalog/home/detail components; `public/contents.js`; `src/configuration-rendering.ts`; frontend runtime/artifact/starter assertions. `AGENTS.md` and `README.md` now retain the exact system font stacks, minimal design constraints, responsive checks and ongoing documentation-maintenance requirement. See [UI evidence](phase6/frontend-simplification.md).
- Decisions: neutral light/dark palette, compact headings/result rows, bounded 1440px listing/1120px reading widths, native filter/contents disclosures. Server omission of empty configuration/notes/related/journey/facet sections and matching contents links; preserve selected zero-count filters, sources/caveats, legacy bookmarks and unknown freshness metadata. No UI framework or remote fonts added.
- Verification: 213/213 runtime and 28/28 built-frontend/artifact/example checks, strict types/import/discovery, clean Astro check/build and generated-config deploy dry run. Chrome checked 90 page/viewport/theme combinations at 320/390/768/1440/3840px without document overflow/dead fragment targets, plus keyboard, mobile/touch, script-blocked search/reading, theme persistence and copy success/failure. Local unthrottled homepage LCP 64ms, CLS 0.00; not production vitals or full accessibility/cross-browser certification.
- Remote effects: none. Existing uncommitted roadmap work and ordinary local DB preserved; only ephemeral public-seed/pilot/starter fixtures used. No commits, pushes, deployment, remote writes, publication, grants or security/cache/auth changes. Existing owner-started local server is not a freshly rebuilt preview; use the documented disposable preview commands for this UI.
- Blockers/exact next action: owner visual review of the simplified UI, then independent compatibility/security/content review and the already-open private-copy/staging/live gates. No release approval is inferred.

#### 2026-10-30 — Final simplified-UI runtime follow-up

- Status: completed locally using the final built Worker, fresh external disposable storage and application writes disabled; no new application defect confirmed.
- Verification: **179 HTTP checks passed**, including all 119 legacy details' section/fragment checks, representations/discovery/HEAD/long searches and expected auth/method/missing rejections. After the ordinary-seed checks, explicitly imported four opt-in starter fixtures there only: 119 legacy / 123 published, zero roles/drafts/creation receipts. Rechecked rebuilt light desktop homepage and dark 320px family/runbook/legacy pages in Chrome; no overflow/dead fragments/console messages/unsuccessful network requests.
- Explorer: recorded **181 root invocations all `ok`**, zero failed/error-bearing spans/5xx/error logs; four explained authentication/method rejection warnings. An unsupported initial telemetry schema query was rejected by Explorer; corrected supported queries confirmed the snapshot. No runtime source correction needed.
- Changed files: added follow-up evidence in `docs/phase6/frontend-simplification.md` and updated this checkpoint/progress log. Raw artifacts remain external; no remote effects, commits, pushes, deployment, grants, production publication or ordinary local DB mutation. Earlier uncommitted work is preserved.
- Preview disposition: earlier temporary harness previews/proxies stopped; existing owner-started port 8787 left untouched. Final rebuilt Wrangler preview remains at **http://127.0.0.1:8790/** with disposable starter fixtures; Explorer is under `/cdn-cgi/local/explorer` there.
- Blockers/exact next action: owner visual review at the current preview. Independent review, approved private-copy rehearsal and actual staging/Access/cache/live rollout approvals remain separate and open.

#### 2026-10-31 — Pagination/live filtering, current-copy rehearsal and production-readiness review

- Status: owner requested scalability, D1/schema/migration/deploy checks and agent/API readiness; separately approved a full private backup/local rehearsal while retaining release gates. Local implementation/rehearsal completed; production remains unchanged.
- Changes/files: progressive `public/catalog-search.js`, catalog SSR markers/shared head slot/Markdown marker, pagination and controller/discovery regressions; local `auth.md` heading fix. `scripts/release_rehearsal.py` excludes only derived optimizer statistics from application preservation, with a new analyzed-database/private-table regression. README, `AGENTS.md`, release runbook, this checkpoint and [new evidence](phase6/scalability-and-production-readiness.md) synchronized. No migrations, public seed or security policy changed in this follow-up.
- Decisions: retain 20/default, 50/max stable summary pagination and compatibility v1 behavior. Direct filters use the same native GET routes with debounce/cancellation/IME/timeout, focus/caret/disclosure, metadata and history preservation; failures fall back to native Search. Response bounds are not constant-cost substring/count/offset queries; large-catalog/load benchmarks and any full-text/cursor redesign remain separate work.
- D1/rehearsal: production read-only schema/integrity/binding checks passed (119 practices, through 0005). Approved full export, unchanged before/after allocator captures and recovery bookmark retained privately. Failed optimizer-statistics comparison diagnosed and retained; fresh offline rehearsal passes. Actual isolated D1/workerd import, restored allocators, 0006–0007, and four ordinary patches twice pass; upgraded application/private data equals offline output. **40 actual local runtime/recovery assertions** pass for recorded prior v0.8 source/current built Worker. Synthetic roles/entries/publication exist only on separate private probe branches; no normal-local or remote effects. Exact deployed artifact/dependencies are not independently matched; live Access/cache remain unverified.
- Verification: **213 runtime + 36 frontend**, strict types/**7 boundary + 3 discovery**, content integrity/four twice-applied patches/**5 + 5 Python**, **9 Python + 7 Node** release checks, generated types, Astro **0 errors/warnings/hints**, build and generated deploy dry run pass; root npm audit reports zero findings. Chrome verified live filtering in **20** light/dark catalog/family viewport combinations, plus IME, metadata/history/caret, stale response and failure/native/no-script journeys. Local catalog LCP **63 ms**, TTFB **10 ms**, CLS **0.00**, clean normal network/console; not production/load/cross-browser certification.
- Production/agent recheck: existing deployment content-profile scanner **Level 5/5**, missing DNS-AID; separate selected discovery passes except old `auth.md` heading, corrected locally only. Public homepage/v1/practice HTML/Markdown/auth/OpenAPI reads return 200, v1 contains 119; `/catalog` and `/api/v2/entries` still return 404. A scanner score is not AEO citation/indexing or complete API certification.
- Blockers/exact next action: independent exact-source/artifact/security/content/dependency review, reconcile exact compatible deployed recovery artifact, approve distinct staging resources/Access design and verify signed/public/browser/cache behavior there. Refresh private recovery state before later explicitly approved production writes/deploy; then rerun production checks. No commit/push/deploy/remote D1 change/security change/live grant/native publication/seed refresh performed.

#### 2026-10-31 — Owner-approved scoped production migration and Astro/v2 deployment

- Approval: owner reported the failed Git build and explicitly approved direct production migration/deployment, accepting independent-review/staging limits. No Access/security changes, live grants or native publication authorized.
- Repair: production Builds had an empty build command and plain Wrangler deploy, incorrectly bundling Astro source. Changed only its commands to `npm run build` and `npx wrangler deploy --config dist/server/wrangler.json`; preserved the remaining trigger settings. Built exact `main` commit `b9bf6a3` successfully; production version `c8f6978d-29a1-4ded-91c9-a6ac0d0cf981` serves 100% traffic.
- D1: fresh private backup/consistent allocators/bookmarks, offline and actual isolated D1/workerd rehearsal passed. Applied 0006–0007 and four ordinary patches. Post-write application/private data matches rehearsal, allocator floors hold, integrity/FKs clean, ledger seven migrations, 119 legacy/119 published, zero roles/drafts/native revisions. Full exports/bookmarks/logs remain private; no public seed refresh.
- Verification: preflight **213 runtime + 36 frontend**, strict types/**7 boundary + 3 discovery**, content integrity, generated types, Astro check/build, deploy dry run and zero root audit findings. Live **9 smoke groups**, **42 requests/11 assertion groups**, **20 catalog/reading viewport/theme combinations**, immediate/debounced filters, history/metadata/caret/select/disclosure, keyboard, native proxied-live-byte no-script forms/pagination/reading pass. Separate HTML/Markdown HITs observed. Production v1 long-search returns 200; discovery/auth read contracts pass. No new third-party readiness score claimed.
- Follow-up files: README, `AGENTS.md`, this roadmap, release runbook/historical evidence and [rollout report](rollout-2026-10-31.md); smoke/tests now require explicit named-bot-cookie opt-in while retaining strict defaults and Worker guards. **9 Node release checks** include new default-rejection and mixed/lookalike/folded-cookie regressions. Neutral pre-release editorial-label corrections in three public documentation assets are local only. All follow-up changes remain uncommitted/undeployed; production is the exact commit above.
- Limits/exact next action: review follow-up and commit/push only on request. Independent review, staging, exact-artifact recovery, authenticated production mutations/retries and purge propagation remain unverified. Plan separately approved staging/authenticated/purge checks before native publication or later production mutations; refresh private recovery inputs first. No grant/publication/security change or throwaway production write was performed.

#### 2026-10-31 — Local restoration of recorded filters and scanning labels

- Request: owner identified lost filters and requested rounded colored labels/legend. Confirmed UI omission, not missing data. Restored six visible recorded-practice filters separately from native taxonomy; added labeled Domain palette/legend, neutral Category/Feature pills, rating text and individually removable filter chips.
- Changed files: catalog v2 filters/queries/projection, new `legacy-discovery.ts`/`filter-presentation.ts`, listing/document/starter readers, native editorial preview projection, shared catalog components, reading heading and CSS. OpenAPI/API docs, WebMCP, agent skill/index/digest, runtime/document/frontend/discovery tests, README/AGENTS and [local evidence](phase6/filter-restoration.md) synchronized. No migrations, seeds, v1/write/cache/security contracts changed.
- Verification: **225 runtime + 37 rebuilt frontend**, strict types/**7 boundary + 3 discovery**, content integrity/four patches twice/**5 + 5 Python**, synthetic release **9 Python + 9 Node**, generated types, clean Astro check/build, generated-config deploy dry run and diff checks pass. **60** actual viewport/theme/script-mode browser combinations pass overflow/width checks, with targeted text contrast, six-filter live/no-script forms, keyboard chips, empty selections, caret/disclosure/history and native pagination evidence. Fresh final-build legacy reading/copy succeeds; no production verification claimed for this follow-up.
- Blockers/exact next action: review changes with owner, then commit/push/deploy only on explicit request. Existing independent-review/staging/recovery/authenticated/purge gaps remain open; production is still `b9bf6a3`. No remote write or rollout performed.

#### 2026-10-31 — v1.1 reconciliation, feature smoke and operational criteria

- Scope/status: owner deferred deployment-approval mechanism changes and requested the remaining audit fixes. Existing `main` push Builds already deployed `53e1f32` (`v1.1`); read-only management inspection reconciled successful build, deployment and serving version. Historical `b9bf6a3` evidence/approval remains intact, superseded only for current-status claims. New changes are local and uncommitted.
- Files: `scripts/release/legacy-filters.mjs`, shared `markup.mjs`, smoke CLI, synthetic filter fixture/release regressions and actual built-Worker release test; new [v1.1 report](rollout-2026-10-31-v1.1.md) and [operational acceptance](phase6/operational-acceptance.md); README, AGENTS, this checkpoint/checklists/decisions, Phase 2/filter evidence and release runbook synchronized. Historical-status banners clarify Phase 3–5, hardening, frontend-simplification and initial-rollout evidence without rewriting their original checks.
- Decisions: opt-in `--expect-legacy-filters` leaves baseline smoke usable for older deployments; verifies individual/conjunctive public-v1 parity, facets/classification/SSR/Markdown, normalization and selected-empty clear links. Native classification remains null with native expectations. No Worker/schema/data/auth/cache/CI/Builds behavior changed. Recovery provenance, accountable roles, proposed 30-minute/24-hour observation and stop criteria are procedures, not claimed completed operations.
- Verification: **225 runtime + 37 frontend**, strict types/**7 boundary + 3 discovery**, content/four ordinary patches twice/**5 + 5 Python**, **9 Python + 12 Node** release checks, generated types, clean Astro check/build, generated-config deploy dry run and zero-finding root audit pass. Three new synthetic tests include old-release rejection, native isolation and ten response-regression mutations. Built Worker passes filter checks while refusing local Access/cache certification. Existing production passes **10/10 anonymous smoke groups with HITs and explicit bot-cookie opt-in**; no native example/publication supplied. Exact-commit CI/current live evidence is in the v1.1 report, separate from this local follow-up.
- Final hygiene: Prettier/diff checks and **174** changed-document relative link targets pass; root full and production-only audits report zero findings. Existing non-failing Node module-type warning is unchanged. Temporary owned debugging file removed; no private evidence copied into the repository.
- Remote effects: anonymous/read-only management reads only; no commit/push, deployment, remote D1 write/export, live grant/publication, recovery or account/security change. Private state/backup freshness was not re-inspected. No approval-mechanism change was implemented.
- Blockers/exact next action: owner reviews local diff, reconciles observed v1.1 scope/limits acceptance and names the recovery operator, release observer and independent reviewers. Plan matching private artifact provenance/recovery, monitoring thresholds/windows and specifically approved staging/Access/signed/purge journeys. Exact-artifact recovery, independent review, staging, authenticated retries/purge and broader certification remain open; no later remote work follows automatically.

#### 2026-10-31 — Owner-requested documentation/probe production release preflight

- Approval/scope: owner explicitly requested commit and production deployment of the verified follow-up. Use the existing `main` push build/deploy integration; no approval-mechanism/CI/Builds configuration changes. No application source, public asset, lockfile, migration, seed or binding delta; no D1 operation, grant/publication, recovery or security change authorized.
- Preflight: working tree contains the reviewed documentation/probe changes only; fetched `origin/main`, checked diff hygiene and re-inspected the current serving version and unchanged Astro build/generated-config deploy trigger. Prior full local checks and ten-group production smoke are recorded above; do not treat them as post-deployment verification.
- Next: commit/push the verified diff, match the new build's exact source to the serving deployment and rerun live filter/HIT smoke. Then retain evidence and resume the still-open independent review, exact-artifact recovery, staging/authenticated/purge and operational-sign-off work. No broader gate closure is implied by this explicit scoped deployment request.

#### 2026-10-31 — Documentation/probe release deployed and read-verified

- Completed: committed/pushed `2e9c50c7a69d4861c4034efd64616ff6ad977e72`; GitHub [Verify 41194796516](https://github.com/DavidJKTofan/cf-best-practices-repository/actions/runs/41194796516) passed for that exact source. Workers Build `eaaf15cc-134b-4085-9680-650e698268df` succeeded at 10:58:06 UTC, deployment `a4957804-3556-4e13-b9c7-29673acd0bde`, version `09d4d277-ddbd-4692-976d-c879ed96c253` at 100% when checked.
- Verification: fresh Astro build, **37/37 frontend**, generated-config dry run and **12 Node + 1 built release** checks passed; earlier full-suite evidence remains above. Post-deploy live smoke passed **10/10 groups** with recorded-filter expectations, strict named-bot-cookie allowance, anonymous private-route denial, discovery and independent HTML/Markdown HITs.
- Transport: HTTPS push/GitHub CLI lacked credentials; existing SSH authentication verified the same repository/remote commit without changing Git configuration. Existing Workers Builds performed deployment; no direct Wrangler deployment was used.
- Scope/limits: application/public assets/dependencies/schema/bindings unchanged; no D1 write/export, grant/publication, recovery or security change. CI, deployment and targeted reads are evidence, not a completed monitoring window, exact-artifact recovery, independent review, staging or authenticated purge gate.
- Evidence handoff: README/AGENTS, this checkpoint, release/filter/runbook and operational records updated after verification. Subsequent evidence-only commits retain the application baseline; their live metadata must be checked separately. Next work is operator/reviewer assignment and specifically approved recovery/staging/authenticated/monitoring journeys, not automatic native publication.

## 13. Repository integration

This roadmap is authoritative in `docs/`; `AGENTS.md` links here and requires checkpoint updates. Do not resume from the superseded external planning copy. Preserve the current production-project description and all repository invariants. Progress/decision evidence must remain public-safe.

## 14. Public references

Recheck APIs/toolchains at implementation time:

- [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/)
- [Astro on Workers](https://developers.cloudflare.com/workers/framework-guides/web-apps/astro/)
- [Astro Cloudflare custom entrypoints](https://docs.astro.build/en/guides/integrations-guide/cloudflare/#changed-custom-entrypoint-api)
- [Astro advanced routing](https://docs.astro.build/en/guides/integrations-guide/cloudflare/#using-advanced-routing)
- [Hono on Workers](https://developers.cloudflare.com/workers/framework-guides/web-apps/more-web-frameworks/hono/)
- [Cache](https://developers.cloudflare.com/workers/cache/) / [purge scope](https://developers.cloudflare.com/workers/cache/purge/)
- [Static Assets](https://developers.cloudflare.com/workers/static-assets/) / [service bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/)
- [D1 migrations](https://developers.cloudflare.com/d1/reference/migrations/) / [import/export](https://developers.cloudflare.com/d1/best-practices/import-export-data/)
- [SASE reference architecture](https://developers.cloudflare.com/reference-architecture/architectures/sase/)

Existing context: `README.md`, `AGENTS.md`, `docs/agent-readiness.md`, `docs/rollout-2026-10-29.md`, `data/content-review-2026-10-29.md`.
