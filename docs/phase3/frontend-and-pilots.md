# Phase 3: Astro field guide and end-to-end pilots

**Status:** completed and verified locally on 2026-10-30. Not staged, published, or deployed. Owner authorized Phase 3 development after local Phases 0–2; that does not authorize remote changes. The [roadmap](../cloudflare-platform-roadmap.md) is the handoff checkpoint.

## Integration and ownership

- `astro.config.mjs` enables on-demand SSR, external CSS and server source maps; sessions are disabled, images pass through, and remote development bindings are disabled. No additional UI framework, KV/image service binding, build-time D1 read, or content authority is introduced.
- `src/astro-worker.ts` preserves the existing uncached gateway and exports `src/entrypoints/astro-reads.ts` as `PublicReads`. This subclasses the domain read entrypoint, adding Astro only for HTML documents. APIs, Markdown, discovery and the cache-owning purge RPC retain their existing modules. `src/index.ts` remains the framework-independent workerd regression entrypoint.
- `src/platform/content-response.ts` applies established headers **after** adapter finalization without buffering HTML. Successful public documents retain the shared `practices` tag and negotiated `Vary: Accept`; errors/cookies are `no-store`/`noindex`, and stale shell validators are removed. The gateway still rate-limits before forwarding reads, strips HEAD bodies, and rejects public writes.
- Production build output is `dist/client` plus `dist/server/wrangler.json`. Only generated configuration is used by `deploy:check` and the approved deployment command. CSS/JS/images remain asset-first; Worker-first additions are limited to `/catalog`, `/catalog.md` and `/families/*`. Default-entrypoint cache stays disabled and `PublicReads` cache enabled.
- Astro/adapter/checker and TypeScript are pinned to the compatible Phase 0-tested versions; TypeScript 7 is not accepted by this Astro checker. CI pins Node 22.23.4. Generated `Env` remains authoritative; no binding interface is hand-written.

## Reading and discovery contracts

| Surface                       | Local behavior                                                                                                                        |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `/`                           | Field-guide orientation, populated family/outcome links, six newest summary cards and ordinary search form; no full-body client fetch |
| `/catalog`                    | Bounded title/summary search, conjunctive facets, active filters, stable sorts and pagination using GET forms                         |
| `/families/{slug}`            | Same components, locked path family and contextual introduction; empty/unknown family is 404, filtered zero matches are 200           |
| `/practices/{id}`             | Full current published legacy/native content, applicability, sources/freshness, validation, metadata, related-family navigation       |
| Explicit `.md` aliases        | Same effective listing or published entry, independent of Accept                                                                      |
| `/index.md`, `/llms-full.txt` | Stream every current published entry in bounded query batches; no silent compatibility truncation                                     |
| `/llms.txt`, `/sitemap.xml`   | Native-inclusive published summary iteration; sitemap includes canonical HTML URLs and populated hubs only                            |

HTML document URLs negotiate Markdown by the existing q-aware preference rules. Existing document query stripping stays intact; **only new catalog/family listings** retain effective search/filter/sort/page state. Family paths override query-family attempts. Default, tracking, preview and draft parameters do not fragment cache keys or expose private data. V2 native `canonicalPath` is now `/practices/{id}`; native `v1Eligible` stays false. V1 bodies, IDs, hashing, insertion/receipt SQL and write/replay purge behavior are unchanged.

`src/content/presentation.ts` maps typed data into shared essential sections for both Astro and Markdown. Stored bodies are inert text and bounded code artifacts, never executed by the application. Architecture topology is a complete textual traffic/trust description, not an inaccessible image dependency. Native Markdown escapes prose and uses fences longer than stored backtick runs; source URLs are validated HTTP(S). Astro escapes text/attributes and `<` is escaped in JSON-LD. Legacy configuration uses the existing escaped renderer.

The old `/#practice-{id}` targets remain in a compact title-only disclosure linking to canonical entries. In Chrome, fragment navigation opens the disclosure and scrolls the target into view without page scripting. Other browsers can open the ordinary disclosure manually; no cross-browser certification is claimed.

The engineering-notebook visual design lives in `src/styles/field-guide.css`: paper/ink colors, serif headings, restrained family accents, local font stacks, light/dark themes and visible keyboard focus. `public/theme*.js` and `code-blocks.js` are optional enhancements. Without scripts, forms, links, full code, topology, sources and CSS system-color preference remain available; inoperative theme/copy controls are not shown.

## Authored pilots: fixtures, not production publication

`test/fixtures/pilots.json` contains three complete, publicly sourced examples. IDs `800001`–`800003` are reserved **only in ephemeral test harnesses**. They are not production allocations, active SQL patches or seed updates.

1. **Application Services / WAF:** observe unexpected methods on one read-only page. Separate expression/action/scope; request-phase Log explicitly requires Enterprise. Include method-contract/CORS checks, dry-run limitations, validation and rollback. Existing practice 18 separately retains its canonical URL and original plan-aware guidance; it is not silently converted.
2. **Cloudflare One / Access + Tunnel:** browser access to a private origin via a public hostname. Separate identity authorization from Tunnel transport, explain routing/DNS/JWT/origin bypass boundaries, replicas versus health-aware load balancing, failures and recovery. No claim of universal licensing or API-client compatibility.
3. **Developer Platform / Workers + D1:** actor-scoped durable creation after a lost response. Include independent SQL/TypeScript files, first-primary receipt recovery, transactional batch, conflict/concurrency/rollback, retention, external-side-effect/cache-purge boundaries, quotas and caller-owned authentication/stream limits.

Each records public-document evidence and distinct editorial/fact/review dates. These are authored teaching examples, not evidence of a deployed WAF rule or Access/Tunnel topology. The actual displayed D1 example is compiled and typechecked against generated Worker types **only inside the isolated test harness**, then exercised against local D1. Runtime application code never evaluates stored code.

### Public references reviewed for the examples

- [Request method field](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.method/), [custom rules/action availability](https://developers.cloudflare.com/waf/custom-rules/), [interoperability/order](https://developers.cloudflare.com/waf/feature-interoperability/), [configuration dry run](https://developers.cloudflare.com/ruleset-engine/rulesets-api/dry-run/).
- [Self-hosted public Access app](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/), [connector Access validation](https://developers.cloudflare.com/tunnel/reference/origin-parameters/#access), [Tunnel routing/replicas](https://developers.cloudflare.com/tunnel/concepts/routing/), [Access JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/).
- [D1 batch](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch), [idempotent retries](https://developers.cloudflare.com/d1/best-practices/retry-queries/), [sessions/replication](https://developers.cloudflare.com/d1/best-practices/read-replication/), [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/).

## Verification and reproducibility

From Node 22.23.4+ and Python 3:

```bash
npm ci
npm test -- --run
npm run typecheck
npm run content:check
npx wrangler types --check
npm run frontend:check
npm run build
npm run frontend:test
npm run deploy:check
```

Clean-install results: **180/180 workerd tests in 9 files**, strict generated-Env types, **7/7 boundary + 2/2 discovery checks**, **4/4 Python upgrade/export tests**, 119-practice integrity and all three active patches twice (including timestamps/sequences), generated binding check, Astro check (**0 errors/warnings/hints**), Astro build, **12/12 built-frontend/artifact/displayed-example checks**, and generated-config deploy **dry run** pass. Formatting, local documentation references and diff whitespace checks pass. The served agent skill digest remains `797d245b527d5dee823cb24cf8afeb380ad383d95222dc91affbf52979257679`.

Local checks are not live-cache, Access-policy or production-copy evidence. The Phase 0 proof was not changed or rerun in this phase; earlier results remain historical.

### Coverage

- `test/catalog-documents.spec.js`: canonical effective query state, family locking, old query stripping, typed fixtures/section parity, safe Markdown fences, error/cookie/header finalization.
- `scripts/test/frontend-runtime.check.mjs`: actual built gateway -> `PublicReads` -> Astro/JSON/Markdown journeys; all 119 legacy detail URLs, native revision parity, headers/HEAD/OPTIONS/methods, empty/missing/error states, v1 exclusion, hostile prose/attribute/JSON-LD/code parsing, unpublished/draft canaries across discovery/exports.
- `scripts/test/frontend-artifacts.check.mjs`: generated cache split/scoped assets/no incidental resources; no server maps, SQL, configuration, fixture data or private modules in actual client artifacts; server maps include gateway/write/read source modules.
- `scripts/test/frontend-pilot.check.mjs`: displayed SQL/TypeScript typechecks, unchanged retry/actor scope/conflict, discarded-response recovery, repeated same-key attempts and receipt-failure rollback. It is a repository example, not an HTTP/auth/purge handler; those boundaries retain the existing application regression tests.
- The self-tested import guard now includes Astro frontmatter and script sources/imports, alongside existing server/browser/public-artifact checks. Discovery schema/skill digest checks remain part of strict types. CI adds Astro check/build and built tests; it remains credential-free with no deploy or remote writes.

### Browser observations (local Chrome only)

- At 320 px, homepage/catalog had no horizontal overflow; at 390 px, developer code stayed inside the viewport and architecture text remained readable.
- Keyboard Tab reached the skip link with a visible 3 px outline; code regions are focusable. Native search submitted successfully with every page script blocked by a local `script-src 'none'` CSP.
- Copy succeeded; simulated clipboard denial displayed the fallback, focused the code and selected its exact text. Theme toggle changed colors/accessibility label and survived navigation; old practice-18 fragment opened its disclosure and linked to `/practices/18`.
- Desktop light/dark and narrow mobile layouts inspected. These are targeted checks, not a complete assistive-technology, WCAG or cross-browser audit.
- Homepage cold local trace (1440×1000, 1× CPU, unthrottled network): **LCP 290 ms, CLS 0.00, TTFB 12 ms**. Render-blocking estimated savings were **0 ms**; no speculative optimization applied. These are localhost lab observations, not field vitals, production latency or an INP/TBT/Speed Index claim. Raw traces/screenshots remain outside the public repository.

### Resolved local findings

- Missing family status initially set inside an Astro component returned 200; load status is now set in page frontmatter before rendering, with a regression test.
- A string-only XSS assertion mistook safe quoted attribute text for executable markup; `parse5` now checks actual script elements, JSON-LD and event attributes, including hostile quotes.
- Wrangler RPC rejection assertions needed async callbacks to capture errors consistently. Both expected conflict/receipt-failure cases pass without changing the displayed repository logic.

## Limits and release gates

- `initial_data.sql`, applied migrations and active content patches were not changed by Phase 3. No real native publication, v2 editorial command, role or protected preview was introduced. Legacy conversion remains blocked.
- A fresh private production-copy migration/receipt/sequence/old-app rollback rehearsal remains unperformed from Phase 2. It is not replaced by public-seed/synthetic tests and must precede remote approval.
- No actual edge hit/purge/replica behavior, deployed canonical agreement, live Access policy, or production rollout verified. `ctx.cache` is not emulated locally. The isolated Phase 0 proof is still not a deployment target.
- Full exports stream; a failure after headers have been sent terminates the stream and is logged rather than returning a silently successful truncated export. Iteration is not a cross-request publication snapshot during concurrent writes.
- Existing v1 long-search failure remains characterized and unchanged; v2/SSR search is bounded literal title/summary search, not full-text or relevance-ranked search.
- `npm audit` reports **7 findings (4 moderate, 3 high)**; `--omit=dev` reports **3 (2 moderate, 1 high)** through the adapter's Wrangler peer/tooling graph (Wrangler -> Miniflare -> Undici). Other findings are in Vitest/plugin tooling. These are not a zero-audit claim; no unrelated automatic upgrades were applied. Public-asset/source-map guards verify publication boundaries, not general dependency exploitability.
- No commits, pushes, deployments, remote database writes, ordinary local database changes or account/security-policy changes performed. Existing uncommitted Phase 0–2 work retained.

**Exact next action:** independently review the Phase 3 gateway/adapter/cache seam, document parity and authored examples; resolve dependency-tooling findings in a separate verified change; obtain the approved fresh private production copy and rehearse before any live rollout/publication. Begin Phase 4 authoring only on owner direction, not as an implied follow-on.
