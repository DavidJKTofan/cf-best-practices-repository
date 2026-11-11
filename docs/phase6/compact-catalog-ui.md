# Compact catalog and practice UI

## Status and scope — 2026-11-11

**Initial compact UI committed/pushed by the owner as `9024693` (`v1.2`), then deployed on request.** The subsequent new-tab/neutral-Level follow-up now serves as `72bae87e-8c70-4f6b-a6e2-f349a738bc24` at 100%, from uncommitted local changes. Latest unchanged smoke passes 10/10, but practice 18 still serves old cached HTML referencing a stylesheet that returns 404; UI verification remains incomplete. See [follow-up evidence and next action](../rollout-2026-11-11-v1.2.md#new-tab-and-neutral-level-follow-up). Original local/live evidence below remains historical. No D1/schema/seed, API payload, query, cache-policy, Access, security-policy, dependency or binding change. No new publication or role grant.

## Presentation

- `EntryList.astro` provides aligned guidance, topic and rating columns at a container width of 68rem or more. Smaller lists stack, including narrow related-content areas on wide screens. Native-only lists show evidence/freshness rather than empty rating columns.
- `EntrySummary.astro` leads with title and the **full existing summary**. No line clamp, generated excerpt or hidden caveat. Domain/topic labels move alongside the text on desktop; active imported rows no longer repeat “Legacy practice” or “Legacy import”. Native type/evidence and non-active lifecycle labels remain.
- `EntryRatings.astro` shares semantic definition lists between results and reading pages. Current Level badges are neutral gray with Mandatory/Recommended/Situational/Optional text, reserving semantic colors for Domains. The original v1.2 used colored Levels; the owner requested their removal in the subsequent follow-up. Impact/Difficulty stay quiet. Rating terms remain accessible when the desktop visual header replaces repeated visible terms. Missing ratings are omitted, never invented.
- `practices/[id].astro` shows classifications and ratings once. “Before you begin” appears only with recorded prerequisites, with a matching contents link. Configuration, expressions and implementation notes remain complete. Sources & freshness retains unknown fact/review dates, unclassified family/maturity and applicability/entitlement qualifications, without migration-process jargon. Source URLs are unchanged; the human-facing imported source link reads “Source documentation”.
- `presentation.ts` displays the existing `legacy-practice` type as “Best practice”; machine type/schema values are unchanged. The homepage's old fragment index is called “Practice quick links”; old IDs/anchors remain.
- Shared CSS retains system fonts, existing neutral light/dark surfaces, Domain colors and bounded 1440px/1120px widths. No new browser script or UI dependency.

## Local verification

Local checks used Node 26.13.0 (satisfies the repository's minimum), existing dependencies and disposable public-seed/pilot harness data, never a private production copy. Preview contains 119 recorded practices plus three test-only pilots; its 122 count is not production publication evidence.

- **225/225 runtime tests**, **39/39 built frontend checks**, strict types, **7 boundary + 3 discovery** checks passed.
- Astro check: **0 errors/warnings/hints**; build and generated-config deploy **dry run** passed. Generated binding types are current.
- Offline integrity: 119 practices, four ordinary patches applied twice, **5 + 5 Python** model/content checks passed. Synthetic release checks: **9 Python + 12 Node** passed.
- New built regressions cover full summaries, grouped ratings/semantic terms, removed import boilerplate, native type/evidence without inferred ratings, detail prerequisites and honest unknown freshness. Existing all-119 detail/fragment checks, six filters, Markdown/JSON parity, escaping, signed editorial fixtures, disclosure/search/history and release probes still pass.
- **70 Chrome viewport/theme/script-mode combinations**: homepage, catalog, Cloudflare One family, practice 18 and typed implementation pilot at 320/390/768/1440/3840px in both themes (50); script-blocked catalog/practice 18 at the same widths/themes (20). No document overflow, broken contents targets or clipped rating values in the scripted matrix; script-blocked pages also remain contained, with native forms and readable code.
- At 1440px, each of the first three catalog rows changed from **231px to 101px** (about **56% less height**), with unchanged summary text. Listing/reading widths remain bounded at 4K.
- Targeted mobile light and desktop dark screenshots inspected. Script-blocked mobile WAF + Recommended submission returned 12 matches; live filtering returned the same count and retained query focus/caret and desktop columns. Keyboard Tab reaches the next title with a visible focus outline. Mobile copy succeeds; an injected clipboard denial gives visible fallback, selected code and no page overflow. Unwrapped code scrolls internally.
- Sampled first-page badge contrast: minimum **5.76:1 light / 8.06:1 dark**, descriptions **5.88:1 / 8.06:1**. This is not a complete accessibility audit.
- One unthrottled local cold-load trace: **LCP 461ms, TTFB 17ms, CLS 0.00**. Render-blocking/cache insights estimated 0ms savings; no unrelated performance rewrite. Normal catalog console had no errors/warnings; all eight observed requests returned 200. Script-blocked previews intentionally produce CSP script rejections.

Resolved check issues: the first new freshness assertion incorrectly assumed whitespace between adjacent definition-list terms; it now checks `dt`/`dd` nodes. The plain formatter lacked an Astro parser; formatting completed with the already cached Astro plugin, without changing dependencies. Chrome's native-select interaction required the visible option label including its count. All final listed checks passed. The existing non-failing Node module-type warning remains unchanged.

## Limits and next action

Initial v1.2 production checks passed **30** viewport/theme combinations for homepage/catalog/practice 18, the then-colored Levels in both themes, exact first-page summary parity, live WAF + Recommended filtering, visible keyboard focus and mobile copy/fallback checks. One live trace recorded **LCP 196ms, TTFB 46ms, CLS 0.00**; normal catalog console had no warnings/errors. These are separate from the local script-blocked/pilot checks above; no native production content or new live no-script matrix was used.

The new-tab/neutral-Level follow-up passes **226 runtime + 42 frontend**, **40 local** viewport/theme/script-mode combinations and **30 live** homepage/catalog/practice 1 combinations. Actual safe new-tab behavior, all four neutral Levels, unchanged Domain colors, native forms, keyboard and code/copy behavior were targeted locally. The latest full smoke passes, but practice 18's stale HTML/missing CSS remains unresolved; this is not a passing practice 18 UI result. Earlier dashboard 429 cause remains unknown. See the release record for exact provenance and scope.

Deployment is complete, not full UI/operational verification. No security exception or assertion relaxation was made. Exact-artifact recovery, independent review, staging, authenticated/purge journeys and monitoring sign-off remain open. Targeted Chrome checks are not full WCAG, assistive-technology, cross-browser, load or field-vitals certification. Evidence updates remain local; no additional commit/push, purge or release is authorized by this document. To reproduce the disposable local preview, run `npm run build` then `npm run preview:pilots -- --no-scripts`.
