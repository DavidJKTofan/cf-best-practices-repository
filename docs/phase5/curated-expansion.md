# Phase 5: curated expansion

**Status:** implemented and verified locally on 2026-10-30; not staged, published to production or deployed. Owner directed Phase 5 after local Phases 0–4. The [roadmap](../cloudflare-platform-roadmap.md) is the resume checkpoint. Independent review, current private production-copy rehearsal, dependency remediation, live-cache/Access verification and release approvals remain open.

## Individual audit, not automatic conversion

The [legacy audit](legacy-audit.md) covers **all 119 existing records**, individually, including Access, Tunnel, Workers, network and operational guidance already present under inherited feature labels. It proposes family/product/type placement and records each entry's caveats. IDs 1–120 (no 64), bodies, sources, expressions, dates and v1 eligibility remain unchanged.

This classification review is **not fact verification**. It does not silently assign current evidence, maturity, entitlements or a new verification date to old guidance. The schema-version-0 adapter remains unclassified publicly. Applying the proposed placements or converting a legacy body still requires a separately reviewed compatibility adapter; do not duplicate those records as native entries to avoid that gate.

## Two useful starting collections

[`data/phase5/starters.json`](../../data/phase5/starters.json) authors four distinct entries, not copies of the three Phase 3 pilots. Each family pairs an implementation with operational recovery:

| Disposable ID | Family             | Authored entry                                                       | Treatment                                                                                                                                      |
| ------------- | ------------------ | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| 810001        | Cloudflare One     | Stage an Access-protected Tunnel hostname without opening the origin | Implementation guide; locally managed YAML, Access audience validation, verified origin TLS and non-proxying catch-all                         |
| 810002        | Cloudflare One     | Diagnose a Tunnel 502 without weakening Access or origin TLS         | Runbook; distinguish 1033 from origin reachability, read-only diagnosis, scoped repair and deny-path regression                                |
| 810003        | Developer Platform | Read D1 summaries with bounded keyset pagination                     | Implementation guide; independent SQL/TypeScript, published columns only, bounded cursors and explicit live-membership limits                  |
| 810004        | Developer Platform | Recover an uncertain D1 write without creating a duplicate           | Runbook; durable actor-scoped receipt recovery, unchanged bounded replay only when application-idempotent, external-effect and restore caveats |

These IDs are **disposable rehearsal identities, not production reservations or citation promises**. Normal seeding remains 119 legacy practices. The starter preview contains 123 published snapshots, of which 119 are v1-eligible; it does not load the Phase 3 pilots as duplicates. Unpopulated families still have no hub.

`src/modules/catalog/starter-collections.ts` owns reading order, not bodies or identity allocation. It selects only active schema-version-1 implementation-guide summaries from `PublishedCatalog` by family and exact reviewed titles. Missing, renamed, ambiguous, unpublished or retired members hide the pair instead of guessing a replacement or reading drafts. Only an unfiltered first family page shows the collection; normal result sorting is independent. HTML and Markdown expose the same order. Review selectors against the actual allocated IDs/titles during publication and after editorial renames.

## Runbook variant and reader compatibility

Runbooks use `schemaVersion: 1`, `type: implementation-guide`, and **`body.variant: operational-runbook`**. This adds an exact, bounded union member without rebuilding the existing content-type-constrained tables. It does not add a `type=operational-runbook` filter or body reads to summary/facet queries.

Required fields are `variant`, `task`, `symptoms`, `diagnostics`, `safeChanges`, `recovery`, `successCriteria` and `rollback`. Mixed guide/runbook fields, missing or unknown discriminators, empty required lists and oversized values fail validation. The existing streamed 64 KiB write bound, source validation, escaping and immutable publication rules still apply.

`src/content/types.ts`, `validation.ts` and `presentation.ts` share the contract. HTML and Markdown use the same task/symptoms/diagnosis/approved-changes/recovery/success/rollback sections. The editorial scaffold/workbench and v2 OpenAPI/read docs/agent skill describe the variant; the skill index digest matches its served bytes. The runbook goes through the same private grants, independent reviewer, exact-version approval and transactional publication as other native entries. No live roles are provisioned.

**Deploy variant-aware readers and update affected v2 clients before publishing any runbook.** A prior typed reader can reject the new body despite the unchanged outer type/schema version. Existing legacy-write/sequence rollback tests do not establish runbook read compatibility. After publication, a code rollback must retain variant support or follow a separately approved, rehearsed content-recovery plan; reverting to an earlier reader alone is not safe. Do not delete frozen revisions, receipts or allocator state as a rollback shortcut. No production rollback/recovery rehearsal is claimed here.

## Public evidence and applicability

Every starter has public sources, prerequisites/exclusions, product-specific availability, validation, failure/recovery and rollback guidance. Editorial modification, fact verification (**2026-10-30**) and review due (**2027-01-30**) are distinct fields. All four retain **`evidence: public-docs`**: isolated example tests are not end-to-end deployment evidence or a reason to mark the entire entry lab-tested.

Public documentation was checked through the Cloudflare documentation MCP; all **15 unique source URLs** resolved with HTTP 200. Link success alone is not fact verification. The authored source lists are authoritative; principal checks included:

- [Access self-hosted public applications](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/), [Cloudflare One plans](https://developers.cloudflare.com/cloudflare-one/), [origin/Access parameters](https://developers.cloudflare.com/tunnel/reference/origin-parameters/), [local ingress validation](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/configuration-file/), [HTTPS origins](https://developers.cloudflare.com/tunnel/troubleshooting/https-origins/), [Tunnel errors](https://developers.cloudflare.com/tunnel/troubleshooting/) and [routing/replicas](https://developers.cloudflare.com/tunnel/concepts/routing/). Browser public-hostname access is not private-IP routing or an API authentication design. Account seats/posture/logging must be checked separately. Never recover by exposing the origin, bypassing Access or disabling certificate verification.
- [D1 bindings/batches/sessions](https://developers.cloudflare.com/d1/worker-api/d1-database/), [first-primary consistency](https://developers.cloudflare.com/d1/best-practices/read-replication/), [indexes](https://developers.cloudflare.com/d1/best-practices/use-indexes/), [Free/Paid pricing](https://developers.cloudflare.com/d1/platform/pricing/), [timeouts/errors](https://developers.cloudflare.com/d1/observability/debug-d1/), [application-idempotent retries](https://developers.cloudflare.com/d1/best-practices/retry-queries/), [Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/) and [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/). A session is not a frozen multi-request snapshot or a cache purge; a timeout does not prove rollback, and a receipt cannot atomically cover external effects.

No fixed cloudflared version is asserted for deployments: record and verify the actual supported version in the target rehearsal. Local ingress syntax/matching does not validate the live IdP, JWT enforcement, origin reachability or failover. No new rule phase/action or universal website-plan entitlement is introduced.

## Active patches versus disposable snapshots

The ordinary active patch list, in order, is:

1. `data/copyable-expressions.sql`
2. `data/content-review-2026-10-29.sql`
3. `data/catalog-taxonomy.sql`
4. **`data/phase5-products.sql`** — public labels for Access, Tunnel, Workers and D1 only; no entries, role grants or legacy assignments.

`scripts/verify-content.py`, `create_d1_schema.sh --local --seed`, `db:seed:local`, Vitest and the built-frontend harness use that list. Every active file is applied twice, comparing full data, timestamps and sequences. This phase adds no migration, binding, dependency or production-seed refresh.

**`data/phase5/local-starters.sql` is deliberately not an active patch. Never apply it remotely or to an ordinary development database.** It creates public snapshots only in disposable tests/previews, without pretending to create real editorial approvals. `scripts/phase5-content.py` deterministically generates it from JSON and checks parity; collision/altered-snapshot/deleted-ID high-water guards fail closed. Tests twice-apply the snapshot and check legacy preservation, publication selection and sanitized export/reload. This is not a production publication mechanism.

To inspect the complete journeys without touching normal local or remote data, use Node 22.23.4+:

```bash
npm run build
npm run preview:starters
# Or include a second URL whose CSP blocks all page scripts:
npm run preview:starters -- --no-scripts
```

Stop with Ctrl-C; fixture state is discarded. To revise authored starter content, review `starters.json`, run `python3 scripts/phase5-content.py --write`, then `npm run content:check`, runtime tests and built-frontend checks. Do not hand-edit generated SQL. Updating the public read skill also requires recomputing its SHA-256 digest.

## Verification and limits

- **210/210 workerd tests**: four authored validation/detail round trips; strict runbook rejection; two populated families/facets and v1 exclusion; repeat-run sequences/revisions; ordered summary-only curation and missing/ambiguous/retired guards; private role/version-protected runbook publication. Earlier authentication, byte bounds, lost-commit/concurrency/rollback, legacy receipts, publication privacy, negotiation, escaping and purge-dispatch regressions remain passing.
- Strict TypeScript, **7/7 boundary + 2/2 discovery checks**, generated binding check, Astro check (**0 errors/warnings/hints**), build and generated-config deployment **dry run** pass. No deployment is performed.
- Offline integrity: 119 legacy records, four active patches twice, generated SQL parity, **5/5 existing upgrade/export + 5/5 Phase 5 Python tests**. The latter cover every audit ID, two native families/123 published snapshots, unchanged legacy rows, repeat-run timestamps/sequences, collision refusal and all four typed export/reload bodies.
- **22/22 frontend checks**: built public artifacts, all legacy links, native representation/discovery parity, signed editorial journey/retry metadata, and five new starter/example checks. Actual displayed D1 SQL/TypeScript typechecks and runs inside workerd: page sizes 1/50, invalid bounds, terminal page, private-body/unpublished exclusion, index plan and changing membership. Existing displayed durable-write examples exercise uncertain commits/concurrency/receipt rollback. The displayed Tunnel YAML passes **cloudflared 2026.9.1** local ingress validation and host/catch-all matching only.
- Targeted Chrome checks: 320 px light/dark, script-blocked family pairs and full runbooks, native form search to the D1 recovery entry, visible skip-link focus, complete recovery/rollback/source sections and horizontally contained code. A cold, unthrottled local desktop family trace measured **LCP 92 ms, CLS 0.00, TTFB 10 ms**, with render-blocking estimated savings **0 ms**; all seven listed requests succeeded and no full-body catalog API request was made. These are local observations, not production vitals, INP/TBT certification or a complete WCAG/assistive-technology/cross-browser audit.

Resolved local test issues: file-level curation fixtures needed explicit published-pointer restoration; the reading-order assertion was scoped to parsed curated anchors rather than earlier alphabetically sorted JSON-LD. These were local harness issues, not live publication failures. No remote partial effects occurred.

Known v1 long-search behavior and previous dependency audit findings remain unchanged. Dependencies were not upgraded, reinstalled or re-audited during Phase 5. No ordinary local development DB, production data/roles, Access policy, crawler policy or account configuration was changed; no commit, push, deployment or remote database write occurred.

## Separately approved publication/release procedure

1. Independently review the audit proposals, source claims/examples, runbook compatibility and Phase 2–4 transaction/auth/export contracts. Resolve tooling dependency findings separately. Obtain owner direction for Phase 6; this document is not release authorization.
2. Obtain an approved current private production export retaining receipts, roles/reviews/contributors, revisions and sequences. Rehearse migrations, active patches twice, old-app writes/replays, variant-aware read compatibility and recovery on an isolated copy. Public-seed/synthetic tests are not substitutes.
3. Prepare isolated staging/Access and a compatible reader/client rollout; no D1 `remote: true`. With explicit approval and a fresh private recovery bookmark/backup, apply only reviewed migrations/active registry patches. Direct SQL does not invoke application purges: coordinate a reviewed cache invalidation/redeployment plan and verify live results separately.
4. Use the protected editorial workflow, not `local-starters.sql`: an authorized editor submits each reviewed `content` envelope, with active lifecycle, and records the **actually allocated ID**. An independent non-contributor reviews the exact version; an authorized non-contributor publishes while the reviewer grant and public base remain valid. Reverify dates/entitlements before publication. Keep identities, grants, review records and receipts private.
5. Verify HTML/Markdown/JSON/source/lifecycle parity, populated curated pairs with real IDs, no duplicates, published-only discovery, v1 exclusion, Access denials, unchanged retries and real cache variants/purge recovery. Browser caches are not cleared by edge purges. Do not treat a local RPC assertion or dry run as this live evidence.
6. Only after approved remote publication and verification, refresh the catalog-only public seed from the private export using the sanitizer; never export private workflow state into the repository. Record public-safe rollout evidence and retain recovery material outside it.

**Exact next action:** independent Phase 5 content/variant review alongside Phase 2–4 release contracts, then owner-authorized Phase 6 rehearsal planning. No live publication is implied by local Phase 5 completion.
