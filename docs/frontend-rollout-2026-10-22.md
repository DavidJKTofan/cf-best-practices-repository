# Frontend rollout verification — 2026-10-22

The frontend improvements and explicit expression/configuration separation were applied to production and deployed successfully.

## Database and deployment

- Rehearsed migration `0004_copyable_expression.sql` and `data/copyable-expressions.sql` twice on an isolated, fresh production export.
- Confirmed **106 practices, 51 explicit expressions, 18 categories, and 30 features**, with no repeat changes, including timestamps. Existing practice IDs, configuration guidance, prerequisites, notes, and other content were preserved.
- Took a D1 Time Travel recovery bookmark before production writes. Recovery details and the pre-write export are retained outside public repository documentation.
- Applied the production migration and data update before deploying the Worker. No pending migrations remain.
- Refreshed `initial_data.sql` from production afterward. Restored it into a fresh migrated local database and verified exact parity with the live API, including expression values and update timestamps. Integrity and foreign-key checks passed.
- All **49 automated tests**, TypeScript checking, and the deployment dry run passed before release.

## Live functional verification

- Checked canonical practice pages at **320, 390, 768, 1024, and 1440 px**, in light and dark themes: no page overflow, wrapped code, and controls at least 44 px tall.
- Verified exact expression copying, separate configuration copying with plan caveats, accessible announcements, line wrapping, clipboard-denial recovery, and saved theme preference.
- Checked the catalog at **320, 390, 768, 859, 860, 1024, 1200, and 1440 px**: mobile sorting, tablet metadata, search, filters, reset/focus behavior, URL restoration, browser Back, synchronized expansion controls, and legacy practice anchors.
- Simulated a failed API enhancement: all 106 server-rendered practice links remained available, and retry restored interactivity without duplicate filter options.
- Verified that the live JSON API matches all rehearsed practice content and the 51 explicit expressions; taxonomy and search reads also passed.
- Repeated HTML and Markdown reads of the homepage, a canonical practice, and API docs returned independent **`Cf-Cache-Status: HIT`** responses with the correct MIME types and `Vary: Accept`.
- Confirmed production canonical URLs, public indexing/retrieval metadata, explicit Markdown routes, **108 canonical sitemap URLs**, OpenAPI **1.1.0**, discovery endpoints, and the served agent-skill digest.
- Verified the merged robots policy, HTTPS redirects, HEAD responses, anonymous public CORS preflight, and Cloudflare Access redirects for unauthenticated dashboard and write-API requests.

## Live Lighthouse results

The mobile homepage and desktop canonical practice page each scored **100 for accessibility, SEO, and agentic browsing**. The localhost canonical warning does not occur on production.

Best Practices remained **81**, with the same two pre-existing deprecations in Cloudflare's injected `/cdn-cgi/challenge-platform/scripts/precursor/main.js`: `StorageType.persistent` and the Protected Audience API. No application console errors were observed in the clean live-page check. This release does not claim a new performance score or field Core Web Vitals result.
