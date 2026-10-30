# Frontend simplification — local only

## Scope and direction

Owner-requested on 2026-10-30: restore the earlier simple, clean reference style while retaining the locally implemented Astro/catalog features. This does not authorize deployment, publication, data changes, or security-policy changes.

- Reuse the earlier neutral light/dark palette and exact system/monospace stacks; no remote fonts, serif display headings, rotated callouts or marketing hero.
- Compact header, clear search, simple result rows and native filter disclosures. Listing width is capped at 1440px; reading pages at 1120px with a bounded article column, including on 4K displays.
- Populated content only: omit empty configuration/notes/related sections and contents links, empty family/outcome journeys, empty source lists and unused facet controls. Retain selected zero-count filters, intentional error/search-empty states and truthful unknown metadata.
- Separate legacy expression/configuration headings directly, rather than nesting both beneath a redundant Configuration heading. Reuse `configurationSections()` for HTML/Markdown presence and duplicate suppression; whitespace-only configuration does not create a section.
- Native contents are initially available without scripts; the small `public/contents.js` enhancement collapses them at 900px and below. Filters, navigation and full reading remain script-independent. Mobile inputs use 16px text and code stays internally scrollable/wrappable.

## Changed areas

`src/styles/field-guide.css`, `src/layouts/FieldGuide.astro`, homepage/detail/catalog components, `src/configuration-rendering.ts`, and `public/contents.js`. Built-Worker tests cover all 119 legacy detail pages and absent/null/blank/expression-only/configuration-only/duplicate cases, typed optional sections, empty taxonomy and selected zero-result facets. Starter assertions check collection structure rather than removed decorative copy. `AGENTS.md`, `README.md` and the roadmap record the persistent design constraints and local-only status.

## Verification checkpoint

- Node 22.23.4: **213/213 workerd tests** and **28/28 built-frontend/artifact/example checks** pass; Astro check reports **0 errors/warnings/hints**. Normal build, strict types/import/discovery checks, offline content integrity (119 practices, four patches twice, generated starter parity and 5+5 Python checks) and generated-config deploy **dry run** pass. Existing module-type warning in the editorial retry test is unchanged.
- Chrome DevTools: **90 page/viewport/theme combinations** across homepage, catalog, two legacy details, rule, architecture, developer guide, starter family and runbook. Widths **320/390/768/1440/3840px**, both themes: no document overflow or missing fragment targets. Reading pages cap at 1120px, listings at 1440px on 4K. Responsive disclosure checks wait for the media-query event/render frame; an initial immediate resize probe observed pending events, not a persistent layout failure.
- Visual checks include light desktop catalog and dark touch/mobile detail. Named controls/headings, visible keyboard skip-link focus, persisted theme choice, line wrapping, exact-text clipboard success and denied-clipboard selection/focus/feedback checked. Token contrast checks: muted text **5.88:1 light / 8.06:1 dark** on page backgrounds; input borders **3.35:1 light / 3.21:1 dark** on control backgrounds. These are targeted checks, not a complete contrast/a11y audit.
- With all page scripts blocked by CSP: CSS follows system light/dark, theme/copy enhancements are absent, native search finds the lost-response guide, complete code/rollback content is present and contents remain natively accessible. No page overflow on the narrow reading journey.
- Cold local unthrottled 1440px homepage trace: **LCP 64ms**, **CLS 0.00**, **TTFB 9ms**. Eight listed successful requests (including two favicon requests); no remote fonts, full-body API download, or console warnings/errors. Render-blocking estimated savings are **0ms**; no speculative loading changes were made.
- Regression setup fixes: updated two assertions tied to intentionally removed decorative copy/HTML ampersand serialization. All new omission/fragment/filter assertions passed. The system Node/npm shim initially selected unsupported Node 22.19.0; verification uses explicit supported Node/npm binaries without changing the global installation.

## Rebuilt Wrangler and Local Explorer follow-up

- Started the final built `dist/server/wrangler.json` with Wrangler 4.156.0, Node 22.23.4, loopback-only `--local`, fresh external disposable persistence and `ALLOW_LOCAL_WRITES:false`. The existing owner-started server on port 8787 and ordinary local storage were left untouched.
- Imported seven migrations, the public seed and four ordinary patches through Local Explorer's D1 API. With only the 119 public legacy snapshots loaded, the homepage omitted empty family/outcome journeys. All **119 legacy HTML detail pages** returned 200 with unique IDs, valid fragment targets and expression/configuration sections matching populated fields.
- **179 HTTP checks passed** across those details, public documents/APIs/discovery, negotiated HTML/Markdown, explicit Markdown, HEAD, long literal searches and deliberate missing/authentication/method rejections. Then explicitly loaded the four opt-in starter snapshots into this disposable database only; both populated families and all four starters' HTML/Markdown/v2 JSON returned 200. Final counts: **119 legacy / 123 published / zero roles, drafts and creation receipts**. No pilots were loaded.
- Chrome rechecked the rebuilt homepage at 1440px light and populated family/runbook/legacy pages at 320px dark/touch: no document overflow, dead fragments, console messages or unsuccessful network requests. Narrow reading contents collapsed as intended. Returning to the homepage showed the now-populated family/outcome journeys and named navigation/search controls.
- Explorer's recorded telemetry snapshot contained **181 root invocations, all outcome `ok`**, zero failed/error-bearing spans, zero HTTP 5xx and zero error logs. Status totals: 175 × 200, 3 × 401, 2 × 404 and 1 × 405. Four warnings matched the intentional unauthenticated/method rejections; 365 informational logs. An initial unsupported telemetry schema `PRAGMA` was rejected by Explorer's read-only query endpoint; subsequent queries used the published schema and supported `SELECT` statements. This was a review-query correction, not an application failure.
- Raw HTTP/telemetry/browser artifacts remain outside the repository. At handoff the rebuilt preview is left running at **http://127.0.0.1:8790/**; Explorer is **http://127.0.0.1:8790/cdn-cgi/local/explorer**. The earlier temporary pilot/starter harness previews and script-blocking proxies were stopped. These URLs last only while the local process runs; reproducible disposable preview commands remain in the README.

## Release limits

No production content, schema, bindings, auth, cache policy or security configuration change. No commits, pushes, deployment or remote writes. Existing Phase 2/6 independent-review, private-copy, staging, Access/cache and approval gates remain open. Local browser results are not production vitals or full WCAG/assistive-technology/cross-browser certification.
