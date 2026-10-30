# Phase 0 Astro + Hono compatibility proof

**Local experiment only. Do not deploy.** This package does not replace the production app. It uses a placeholder D1 identifier, no routes, no real Access application, and no remote bindings. See the [roadmap](../../docs/cloudflare-platform-roadmap.md), [decisions](../../docs/phase0/direction-and-compatibility.md), and [contract inventory](../../docs/phase0/contracts.md).

## What it tests

- Documented Astro Cloudflare custom entrypoint, top-level named `PublicReads` and real `ctx.exports` loopback dispatch.
- Hono route groups delegating to existing gateway/Access/validation/creation, without copying security logic.
- Existing practice detail rendered by Astro; unchanged legacy JSON/Markdown read paths; escaped stored content.
- Final cache headers applied after adapter finalization; existing primary-read and purge implementation retained.
- Creation using RS256 JWTs signed by an ephemeral **local** JWKS fixture; missing/invalid tokens, durable receipt replay/conflict, streamed byte limits and malformed data.
- Build output preserves scoped asset-first routing and per-entrypoint cache configuration, emits server source maps, and keeps server artifacts out of public assets.

The homepage deliberately lists only three preview entries, HTML is noindex, and final metadata/dashboard/discovery UI is not implemented. This is a compatibility seam, **not** a behavior-identical replacement or production recommendation set.

## Reproduce

Install the root project's existing dependencies first (`npm ci` from the repository root). This proof imports unchanged production modules from `../../src/`; their existing dependencies resolve from the root.

Within this directory, use **Node >=22.23.4** (required by the pinned Astro release):

```sh
npm ci
npm run verify
```

If the default Node is older, select an isolated runtime without changing it globally:

```sh
npm exec --yes --package=node@22.23.4 -- npm ci
npm exec --yes --package=node@22.23.4 -- npm run verify
```

`verify` generates binding types, runs Astro checks/build, tests the built Worker in local workerd via Wrangler's test harness, checks artifacts, then runs a **deployment dry run only**. No credentials/production database are required. Test D1 storage and JWT signing keys are ephemeral. The JWKS server binds only to loopback and is closed with the harness. `.check.mjs` filenames keep these Node-runner checks out of production's Vitest suite.

For interactive local exploration, initialize only this package's local D1 (after selecting the supported Node runtime):

```sh
npx wrangler d1 migrations apply DB --local
npx wrangler d1 execute DB --local --file=../../initial_data.sql
npm run dev
```

Do not add `remote: true`, production IDs, `ALLOW_LOCAL_WRITES`, or deployment scripts. Tests use signed JWTs rather than a deployed or local-write bypass. The interactive experiment intentionally has no dashboard authoring UI. Generated Env types, `.astro/`, `dist/`, and `.wrangler/` are ignored locally; exact package versions and lockfile are committed deliverables only when separately authorized.

## Toolchain decision

Astro 7.4.4 / adapter 14.4.3 / Hono 4.13.14 / Wrangler 4.151.0. TypeScript 6.0.3 is isolated here because Astro checker 0.9.12 supports TypeScript 5/6, not production's TypeScript 7. Do not use `--force` or `--legacy-peer-deps` to hide this mismatch. Sessions are disabled and image handling is passthrough to avoid incidental KV/Images provisioning.

The compatibility date is **2026-10-19**, the newest supported by pinned Wrangler's workerd. A trial using 2026-10-30 built successfully but failed at runtime startup; a successful build alone therefore does not establish runtime compatibility. Upgrade and reverify the toolchain before advancing this date. Tests import Wrangler through its CommonJS default export to avoid Node ESM named-export interop failures.

## Verification record

2026-10-30: isolated `npm ci` succeeded. `npm run verify` passed type generation, Astro check (0 errors/warnings), build, **12/12 runtime/artifact checks**, and deployment **dry run**. Production's separate **75/75** tests plus types, catalog integrity/repeat-run checks, generated types and dry run also pass. No production app/dependency/config/data changes.

**Historical search defect, now corrected in the shared query:** legacy search permits 200 UTF-16 code units but D1 limits LIKE/GLOB patterns to **50 bytes**, including added `%` and escape bytes. Earlier proof runs characterized HTTP 500/no-store. The separate [post-roadmap hardening](../../docs/phase6/development-hardening.md) now uses bound literal substring matching without changing normalization; one of the 12 checks retains the direct D1 LIKE-limit proof and verifies a successful long-search API result. The proof's Wrangler/lockfile and generated types were refreshed with the same patched root tooling. Neither these checks nor clean audits establish release approval or live cache/Access behavior.

**Not established locally:** actual Workers Cache hits/variants/purges, replica-lag behavior, real Access edge policy coverage, production source-map stack resolution, production billing, full frontend/discovery parity or accessibility/performance certification. A successful local purge RPC is a no-op because `ctx.cache` is not emulated. Owner-approved staging/live verification is a later gate, not permission to deploy this proof.

## Disclaimer

Unofficial educational experiment, not an official Cloudflare product or official guidance. Provided **AS IS**, without warranty; validate suitability before use. The [repository README disclaimer and limitation of liability](../../README.md#disclaimer) apply in full. Existing licenses, copyrights, and trademark notices are unchanged.
