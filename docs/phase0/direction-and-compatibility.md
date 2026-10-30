# Phase 0: direction and compatibility review

**Date:** 2026-10-30. **Status:** local proof complete; owner directed Phase 1 continuation on 2026-10-30. These proposals are the working direction, not final publication/UX approval or deployment verification. See [roadmap](../cloudflare-platform-roadmap.md), [contracts](contracts.md), [wireframes](wireframes.md), and [experiment](../../experiments/phase0-astro-hono/README.md).

## Phase 0 decisions (working direction, not rollout approval)

### D0-01 — One modular Worker, explicit service boundaries

Start with a catalog query service, editorial command service, taxonomy, discovery, and rendering boundaries in one deployable Worker. Keep uncached gateway -> cached `PublicReads.fetch()` and protected commands -> purge RPC. Product families are taxonomy, not microservice boundaries. This avoids distributed transactions and service-per-family duplication while keeping later extraction possible through service bindings. Extract source checks/import/indexing when ownership, workloads, or release/security isolation justify it.

### D0-02 — Astro presentation, thin Hono routing, legacy adapters

Test the adapter's documented custom `wrangler.main` + `@astrojs/cloudflare/handler` integration. Preserve a top-level named `PublicReads` export and re-use the existing gateway/Access/creation implementation rather than porting security logic into a framework.

The experiment subclasses the existing read entrypoint, changes only selected HTML presentation, and delegates Markdown/JSON to the existing code. Hono mounts route groups in the uncached gateway. Apply authoritative cache/security headers **after** adapter response finalization, stream the body, and refuse shared caching when cookies appear.

This proves a compatibility seam, not that Hono is necessary or that the current wrapper should be copied into production. Phase 1 should replace the pass-through grouping with thin feature routers incrementally; use Astro-only endpoints if Hono brings no meaningful boundary/value. No second client UI framework or stored MDX.

Pinned proof toolchain: Astro **7.4.4**, Cloudflare adapter **14.4.3**, Hono **4.13.14**, Wrangler **4.151.0**, Astro checker **0.9.12**, TypeScript **6.0.3**, Node **>=22.23.4**. The default development Node is older; select a newer runtime for the package only. Astro's checker rejects production TypeScript 7 via peer requirements; do not force-install it. Production dependencies/config remain unchanged.

Disable sessions and dynamic image services; verify generated config does not add KV/Images or widen Worker-first routing. Build with no live account/D1 credentials. Audit actual source maps and client assets, not just `upload_source_maps`.

Compatibility finding: Wrangler 4.151.0's bundled workerd rejects dates newer than **2026-10-19**. The proof pins that recent supported date (rather than claiming today's date was exercised); production's date is unchanged. A future toolchain/date upgrade requires a fresh runtime/build check. Wrangler's CommonJS package also requires a default import for the test harness/SQL splitter in these Node ESM tests.

The proof also exposed a pre-existing legacy search defect: the 200-character normalizer can exceed D1's 50-byte LIKE-pattern limit. See [the contract inventory](contracts.md#coverage-gaps-and-required-future-additions). This needs a separately reviewed fix before search adoption; the proof characterizes the current failure rather than editing production search incidentally.

### D0-03 — D1 authority, immutable published revisions, bounded typed bodies

Proposed additive relational design (names illustrative, no migrations applied):

| Entity                                      | Responsibility                                                                                                    |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| CatalogEntry                                | Stable `practice_id`, primary family, current published revision pointer, deprecation/supersession                |
| EntryRevision                               | Immutable revision ID, schema/body type version, metadata snapshot, validated JSON body, editorial/evidence dates |
| EntryDraft                                  | Protected editable working copy, optimistic version, review state; never selected by public queries               |
| Product / Family / ProductFamily            | Stable slugs, editable labels/aliases and cross-family associations                                               |
| EntryProduct / EntryOutcome / EntryRelation | Queryable many-to-many relationships                                                                              |
| RevisionSource                              | Public HTTP(S) sources scoped to the revision and claims verified                                                 |
| PracticeCreations                           | Existing private v1 idempotency receipts, retained unchanged                                                      |

All public reads join the published pointer, not “latest revision”. Public metadata/taxonomy associations must describe the published snapshot, not an unpublished draft. Publishing freezes a validated revision and updates its pointer/associations atomically; conflict/idempotency rules and SQL are Phase 2/4 design work. D1 is the sole runtime authority; no second CMS store.

Bodies use a discriminated `type` and `schemaVersion: 1`; metadata and public sources are shared. Initial types: `recommendation`, `rule-policy`, `reference-architecture`, `implementation-guide`; add `operational-runbook` only with a real authored example. “Developer pattern” is a reading treatment of `implementation-guide`, not a sixth competing type.

Common envelope sketch:

```json
{
	"practiceId": 18,
	"revisionId": "immutable-revision-id",
	"type": "rule-policy",
	"schemaVersion": 1,
	"title": "Observe methods unexpected for a specific endpoint",
	"summary": "An endpoint-scoped example, not a universal HTTP method block.",
	"primaryFamily": "application-services",
	"products": ["waf"],
	"outcomes": ["protect-applications"],
	"applicability": { "requires": ["Validate expected methods per endpoint"], "excludes": ["Universal deny list"] },
	"sources": [{ "url": "https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.method/" }],
	"evidence": { "status": "documentation-reviewed", "factVerifiedAt": null },
	"body": {
		"phase": "http_request_firewall_custom",
		"expression": "<preserved example>",
		"action": "<plan-aware choice>",
		"rollout": [],
		"rollback": []
	}
}
```

This is a design example, **not a validated API payload or copyable deployment**. Real runtime validators must reject unknown versions/types, enforce the existing 64 KiB streamed request bound plus bounded strings/arrays/nesting, validate public sources, and require type-specific sections before publication. Do not invent verification dates when backfilling. Never execute blocks as MDX or trust uploaded SVG/HTML.

### D0-04 — Explicit v1 eligibility; no lossy auto-coercion

- Preserve **every existing practice ID and legacy representation**, including non-rule recommendations. v1 is not restricted retroactively to rules.
- Existing writes keep their normalized payload shape, operation namespace and durable receipts. Adapters do not add v2 defaults before hashing an old request.
- New typed entries enter v1 only through an explicitly authored, validated legacy projection; no automatic architecture-to-rule coercion or accidental publication.
- Proposed v2 read responses use published summaries/details, bounded page size and allowlisted sort with an ID tie-breaker. Exact pagination/facet contracts require Phase 2 design/tests; they are not implemented routes.
- Maintain explicit numeric `/practices/{id}` canonicals. No slug rename is necessary to support product hubs.

### D0-05 — Taxonomy is independent of outcomes and types

| Stable family slug     | Display label             | Example products / aliases                            |
| ---------------------- | ------------------------- | ----------------------------------------------------- |
| `application-services` | Application services      | WAF, API Shield, Bot Management, DNS, CDN/cache, TLS  |
| `cloudflare-one`       | Cloudflare One            | Access, Gateway, Tunnel, Cloudflare One Client (WARP) |
| `developer-platform`   | Developer Platform        | Workers, D1, R2, Queues, Workflows, Durable Objects   |
| `network-services`     | Network services          | Cloudflare WAN, Magic Transit, Network Interconnect   |
| `platform-operations`  | Cross-platform operations | Terraform, account governance, logs, deployment       |

Cloudflare WAN and Tunnel may be associated with several families; use one primary placement and related hubs rather than duplicate entries. Product labels can change without changing IDs/URLs. Hide unpopulated hubs at launch. Outcome seeds: protect applications, connect private applications, build reliable services, operate the platform. These are editorial labels, not official Cloudflare taxonomy.

## Pilot content specifications

These are **schema/UX fixtures**, not newly published recommendations. Sources were checked as design inputs on 2026-10-30; deployment testing is not claimed.

### A. Existing Application Security policy — practice 18

- Preserve ID/title/source/caveats and expression from `initial_data.sql`; do not silently edit content during framework adoption.
- Type `rule-policy`, primary `application-services`, WAF; outcome protect applications.
- Required body: product + request phase, endpoint-scoped conditions, separate action, availability caveats, observe/enforce/rollback and validation.
- Check method field and request-phase Log entitlement; no assertion that this rule fits all endpoints or that browser challenges work for APIs.
- Sources: [method field](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.method/), [custom rules plans](https://developers.cloudflare.com/waf/custom-rules/), [actions](https://developers.cloudflare.com/ruleset-engine/rules-language/actions/).

### B. Cloudflare One architecture — browser access to a self-hosted HTTP app

- New ID assigned only when later publishing; no production seed insertion in Phase 0.
- Type `reference-architecture`, Cloudflare One; products Access + Tunnel, optional device posture explicitly separate.
- Body: scope/assumptions; components; flows/trust boundaries; DNS and routing; identity policy; availability/failures; validation; safe rollback; trade-offs; text diagram.
- Flow: browser -> hostname protected by Access -> policy/IdP authentication -> Cloudflare -> outbound-established Tunnel -> origin. Tunnel is connectivity, **not automatic Access authorization**. Confirm a matching Access application/policy before exposing the route, validate origin trust/bypass paths, and plan connector failure testing.
- A public hostname protected by Access differs from private-IP client routing; do not mix prerequisites or imply a device client is mandatory for browser-only access. Entitlements/device checks remain deployment-specific.
- Sources: [application types](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/choose-application-type/), [self-hosted public app](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/), [SASE reference](https://developers.cloudflare.com/reference-architecture/architectures/sase/), [JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/).

### C. Developer implementation pattern — durable creation on Workers + D1

- Type `implementation-guide`, Developer Platform; Workers + D1; outcome build reliable services. Existing app supplies the implementation subject, not a newly generalized recommendation.
- Body: intended failure scenario (lost response after commit), assumptions, file-oriented artifacts (validation/command/repository), generated bindings, receipt schema, transactional batch, bounded transient retries, tests, observability, rollback and retention/cost trade-offs.
- A durable actor/key receipt and payload hash distinguish retry recovery from arbitrary repeated writes. `first-primary` cache fill and purge attempt are separate from the atomic write. Do not promise exactly-once HTTP delivery or global immediate cache visibility.
- Sources: [D1 batch/session API](https://developers.cloudflare.com/d1/worker-api/d1-database/), [retry safety](https://developers.cloudflare.com/d1/best-practices/retry-queries/), [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/).

## Evidence and open gates

The experiment README records actual check results once completed. The existing 75 tests remain the compatibility baseline; build-level tests add evidence, not a replacement for full production regression coverage.

- [x] Local build/type/runtime/artifact checks complete and recorded: Astro check/build, **12/12** checks against built Worker/artifacts, type generation, deploy dry run. Existing production **75/75** tests and all baseline verification checks also pass.
- [x] Owner directed continuation using Phase 0 as the working baseline; final family labels, pilot publication and UX remain subject to their later phase gates.
- [x] Phase 1 behavior-preserving structural work authorized on 2026-10-30; no schema/content/frontend replacement or search behavior change included.
- [ ] Separate staging deployment approved and actual cache variants/purge + Access policy coverage verified before production adoption.

Phase 0 changed no production data, migrations, root dependencies/config, account policies, deployments, commits or pushes. Subsequent local implementation is tracked separately in the roadmap.
