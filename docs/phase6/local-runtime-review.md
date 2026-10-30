# Local Wrangler and browser review

**Reviewed locally on 2026-10-30; not staged or deployed.** The owner requested `npx wrangler dev`, browser/console inspection and review using [Local Explorer](https://developers.cloudflare.com/workers/local-development/local-explorer/). No new application defect was confirmed in the exercised journeys. This supplements [development hardening](development-hardening.md), not the private-copy, independent-review or [release gates](rehearsal-and-rollout.md).

## Setup and data isolation

- Rebuilt the application with Node 22.23.4 and started Wrangler 4.156.0 against the generated `dist/server/wrangler.json`, not raw Astro source.
- Bound the server to loopback and explicitly used local bindings, a fresh external disposable persistence directory and `ALLOW_LOCAL_WRITES:false`. Ordinary `.wrangler/state` storage was not changed.
- Retrieved Local Explorer's OpenAPI schema from `/cdn-cgi/local/explorer/api`; used its local D1 API to import seven migrations, the public seed and four ordinary active patches into the initially empty review database.
- Reviewed the ordinary 119-record public catalog first. Then explicitly imported `data/phase5/local-starters.sql` into that disposable database only: 123 published snapshots, while v1 remained at 119 records. Final counts: zero editorial roles, drafts and creation receipts.
- Opened the app and Local Explorer's Traces view in an isolated Chrome context. A separate temporary, loopback-only, GET/HEAD proxy added `script-src 'none'` for no-script browser checks; it was stopped afterward.

The local server was started with this configuration (use a newly created disposable directory):

```bash
npx wrangler dev --config dist/server/wrangler.json --local \
  --ip 127.0.0.1 --port 8787 --persist-to "$PRIVATE_REVIEW_DIR/state" \
  --var ALLOW_LOCAL_WRITES:false --show-interactive-dev-session=false
```

Application: `http://127.0.0.1:8787/`. Explorer: `http://127.0.0.1:8787/cdn-cgi/local/explorer`.

## HTTP and browser results

- **44 HTTP checks passed** against the public seed: long ASCII/multibyte/wildcard-heavy literal searches, a positive complete 200-character description search, public documents/APIs/discovery resources, HTML/Markdown preference and exclusion handling, `Vary: Accept`, HEAD/OPTIONS, rejected writes/previews and a missing practice ID.
- Both populated family pages and all four starters' HTML/Markdown/v2 JSON detail URLs returned 200 after the opt-in import.
- Browser journeys covered homepage, both populated families, catalog, both runbooks, the D1 implementation guide, legacy practice 18 and API documentation. Public pages had no console messages or unsuccessful network requests. Typical SSR pages used seven document/asset requests; they did not fetch the full-body catalog API.
- Native mobile catalog search for `D1` returned the two expected starters through a GET form. No-script search and next-page navigation also worked; the complete D1 guide and both configuration blocks remained server-rendered without enhancement controls.
- Light-mode catalog screenshot at 390 px and dark-mode detail screenshot at 320 px were inspected. At 320 px, homepage, family, runbook, legacy and implementation-guide documents stayed within the viewport. Long code scrolled inside its own block; the wrap control changed `aria-pressed` and wrapped text without page overflow.
- Sampled public pages had no duplicate IDs or unnamed controls. This is a limited DOM/accessibility-tree check, not an assistive-technology or WCAG certification.
- The unauthenticated editorial shell loaded, but its private listing request correctly returned 401 and Chrome reported that rejected resource. Script-blocked checks intentionally produced CSP console errors. Neither is an unexpected runtime failure or evidence of successful authenticated editing.

## Local performance observation

One cold-cache, unthrottled Chrome homepage trace on the local machine:

| Metric | Observation | Assessment                |
| ------ | ----------- | ------------------------- |
| LCP    | 116 ms      | Good in this local sample |
| TTFB   | 11 ms       | Good in this local sample |
| CLS    | 0.00        | No measured layout shift  |

The trace estimated **0 ms** savings from render-blocking resources; no optimization is recommended from that insight. These are localhost lab observations, not deployed performance, real-user data or an INP measurement.

## Worker logs and Local Explorer

Final telemetry snapshot after browser/no-script journeys:

- **129 root invocations, all outcome `ok`**; zero failed/error-bearing spans and zero HTTP 5xx responses.
- Root status totals: 111 × 200, 8 × 204, 6 × 401, 2 × 404 and 2 × 405.
- 254 informational logs, **nine expected rejection warnings**, zero error logs. Wrangler output agreed with the Explorer data; no startup exception was observed.
- Warnings corresponded to deliberate method/authentication checks, the unauthenticated dashboard and one incorrect initial probe of a nonexistent editorial route. The probe was corrected to `/dashboard/api/catalog`; the 44-check matrix then passed. A telemetry query initially used an incorrect log timestamp column; the corrected query confirmed only expected warnings.
- Inspected binding-span timing aggregates, but import/setup traffic is mixed into them; no application D1 latency claim is made.

Explorer's UI may count deliberate 4xx responses as errors even when invocation outcome is `ok`. Queries inspected status, outcome, span error and log level separately. Raw logs, HTTP results, screenshots, trace and telemetry artifacts remain outside the repository.

## Limits and next action

Workers Cache and the deployed Access edge are not emulated locally; production-looking Worker trace URLs are Wrangler's local hostname rewriting, not remote application requests. Cache HIT/purge/replica freshness, valid-role editing/publication/retries, account security policy, actual private-data recovery and deployed canonical agreement remain unverified here.

Only this evidence and the roadmap/hardening handoff were edited for the review. No commit, push, deployment, remote database write, production-data export/read, live role grant, native production publication, seed refresh or account/security change occurred. Pre-existing changes were preserved.

**Exact next action:** independently review the implementation and these findings, obtain an approved current full private export with consistent allocator capture and verified baseline, then run offline and actual isolated workerd/old-reader/editorial recovery rehearsals. Obtain explicit staging/Access approval before provisioning or deployment; keep the private-copy and live rollout gates open.
