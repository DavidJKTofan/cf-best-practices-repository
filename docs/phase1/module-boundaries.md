# Phase 1: behavior-preserving module boundaries

**Status:** completed locally on 2026-10-30; ready for independent review, not staged or deployed. See the [roadmap checkpoint](../cloudflare-platform-roadmap.md) and [baseline contracts](../phase0/contracts.md).

## Module ownership

| Boundary                     | Modules                                                            | Responsibility                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| Worker exports               | `src/index.ts`                                                     | Preserve the default gateway and named `PublicReads` export; no configuration/binding changes                          |
| Uncached gateway             | `src/entrypoints/gateway.ts`, `read-gateway.ts`                    | Request IDs, established error envelopes, read methods/rate limits/normalization, loopback fetch and HEAD handling     |
| Cached entrypoint            | `src/entrypoints/public-reads.ts`                                  | JSON/document dispatch, first-primary sessions, representation headers, cache-owning purge RPC                         |
| Route groups                 | `src/api/{public,legacy,editorial}.ts`                             | Thin Hono groups for existing documents, v1 reads and protected creation; no SQL, auth replacement or new endpoints    |
| Catalog reads                | `src/modules/catalog/{filters,queries}.ts`, `src/practice-data.ts` | Existing effective filters, parameterized SQL and shared legacy projection                                             |
| Taxonomy reads               | `src/modules/taxonomy/queries.ts`                                  | Existing category/feature projections and ordering                                                                     |
| Durable persistence          | `src/modules/catalog/creation.ts`                                  | Unchanged v1 operation/payload hashes, atomic practice/receipt batch and bounded application-idempotent retry          |
| Command orchestration        | `src/practice-creation.ts`                                         | POST-only, Access identity, key/body validation, database error mapping, saved-event logging and awaited purge attempt |
| Platform policy              | `src/platform/{cache,public-http,rate-limit}.ts`                   | Shared TTLs/tags, entrypoint-scoped purge helpers, public read CORS and fail-open rate limiter                         |
| Existing isolated safeguards | `src/{access,request-body,practice-validation,http,d1-retry}.ts`   | Retained without semantic edits; already separate modules, so no cosmetic relocation                                   |
| Presentation/discovery       | `src/public-content.ts` and existing rendering/negotiation modules | Existing escaped HTML/Markdown/discovery; SQL now delegates to catalog queries                                         |

`src/read-api.ts` remains the explicit `READ_ROUTES` registry and preserves its earlier exports. `src/practice-creation.ts`, `src/public-content.ts` and `src/index.ts` also preserve their prior public module exports so existing tests and the isolated Phase 0 proof need no import rewrites. There is only one implementation of each extracted operation.

## Hono integration decisions

- Pin **Hono 4.13.14**, the version exercised by Phase 0. No Astro dependency/build, compatibility-date change, new binding or frontend rewrite in this phase.
- Build route groups per dynamic request and capture a typed request scope. Production bindings still use generated `Env`; local-write opt-in retains the existing `RuntimeEnv` extension. Do not cast or rely on Hono's loosely typed `executionCtx.exports` for loopback/purge calls. No request/identity state is stored globally.
- Match the raw `URL.pathname`, not Hono's default decoded path. Preserve case, trailing slashes, encoded paths, invalid practice IDs, bare `/api`, unknown API preflights and method/error precedence.
- Hono normally strips all HEAD bodies. A GET-only **routing view** avoids changing legacy raw-handler error/asset responses; every feature handler still receives the original request. The existing read gateway alone normalizes upstream HEAD to GET and strips successful read bodies. The HTTP server suppresses HEAD bodies on the wire as before.
- Keep the static-asset fast path outside router construction. Keep framework error defaults out of responses; the existing gateway owns errors, and handlers own CORS/cache/security headers. Never consume request bodies with Hono before Access and the bounded parser.
- `PublicReads` remains a real `WorkerEntrypoint<Env>` re-export, not a router object or custom read RPC. Writes/replays invoke its purge RPC; the actual cache helper uses that entrypoint's `ctx.cache`.

## Import and artifact guard

`npm run typecheck` now includes `npm run boundaries:check`, so existing credential-free CI enforces the guard without changing deployment behavior. The Node-runner self-tests use `.check.mjs` names to stay outside workerd's Vitest suite.

`scripts/verify-boundaries.mjs` parses server/browser imports, re-exports, type imports, literal dynamic imports, CommonJS imports, inline scripts and static HTML script references. It rejects imports across `src/` and `public/`, production imports from tests/experiments, computed module imports, non-local browser modules, unresolved local modules, symlinks and common server/configuration artifacts in public assets. It checks every browser module, including dependencies. This is an import/artifact guard, not a general secret scanner or a sandbox for arbitrary JavaScript.

The parser is a pinned **development-only** dependency. TypeScript 7 no longer provides the old `createSourceFile` API from its root export; use a separate parser rather than downgrading the compiler or depending on its unstable API. Wrangler-generated binding/runtime types remain authoritative and checked separately with `wrangler types --check`.

## Compatibility evidence and limits

- The original **75 runtime tests** passed before extraction.
- **34 gateway/cache characterization tests** passed against the pre-refactor implementation. Final **117/117 runtime tests in 6 files** pass, including first-primary API/document fills, the original static asset async-error fast path, fixed legacy receipt hashes/replay/conflict and the unchanged long-search failure.
- Root `npm ci`, `npm test -- --run`, `npm run typecheck` (including **6/6** boundary-guard self-tests and the source/artifact scan), `npm run content:check` (119 practices, repeat-run integrity), `npx wrangler types --check`, `npx wrangler deploy --dry-run`, formatting and `git diff --check` pass.
- The isolated proof's Node 22.23.4 `npm run verify` passes again: type generation, Astro check/build, **12/12 built-Worker/artifact tests** and deploy dry run. No proof source/config/dependency changes were needed. These checks are local evidence, not a deployment claim.
- No migrations, data patches, seed changes, public assets/discovery bytes, Access/validation rules, operation namespace, normalized payload ordering or receipt retention changes.
- The pre-existing D1 50-byte LIKE-pattern limit can still cause a long search to return **500/no-store**. Characterization is not a fix or desired future search contract; correct it separately before Phase 2 search development.
- Local workerd, mocked cache ownership checks and deploy dry runs do not establish live cache hit/purge/replica behavior or edge Access policy coverage. Approved staging/rollout checks remain mandatory.
- The existing development toolchain has **8 npm audit findings (4 moderate/4 high)**; no unrelated toolchain upgrade is bundled here. `npm audit --omit=dev` reports **0** vulnerabilities.

## Next boundary

Review these structural changes independently. Before Phase 2 implementation, agree the separate long-search correction and additive schema/v2 contracts. Keep Astro presentation and rich pilot publication for their later gates. No commit, push, deploy, remote database write or security-policy change is authorized by this document.
