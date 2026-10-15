# SEO / AEO and agent-readiness review — 2026-10-15

## Observed baseline

- [Agent Readiness report](https://isitagentready.com/db.automatic-demo.com): **20/100, Level 0**. Missing sitemap, Link headers, Markdown negotiation, API catalog, auth guidance, skills index, and capability discovery. Some advanced protocol checks also fail because those services are not implemented.
- At baseline, the homepage returned `X-Robots-Tag: noindex, nofollow` and a matching robots meta tag. Practice content loaded through JavaScript; fragment-only permalinks did not expose standalone crawlable pages.
- The baseline `/robots.txt` combined Cloudflare-managed rules with the repository's former opt-out policy, including contradictory Content Signals. The scanner's passing bot-rules checks only detected that rules existed; they did not establish that useful agents were allowed.
- Chrome DevTools production lab trace, unthrottled desktop: **LCP 629 ms, TTFB 152 ms, CLS 0.00**. Render-blocking/cache insights estimate 0 ms savings. No CrUX field data was available.
- Production desktop Lighthouse: **SEO 66, accessibility 100, best practices 81**. This is a pre-change baseline, not a deployed result.

## Implementation

- Render initial homepage summaries/links from D1; add standalone full-detail `/practices/{id}` pages with canonical, social, TechArticle, and Breadcrumb metadata. Use real database update timestamps, never scan/deployment times, for freshness.
- Serve HTML by default and `text/markdown; charset=utf-8` for explicitly preferred `Accept: text/markdown` on homepage, practice pages, and API docs. Respect quality/exclusion values. Add explicit Markdown URLs, `Vary: Accept`, anonymous CORS, Content Signals, and RFC 8288 discovery links.
- Generate the sitemap and agent index from current primary D1 reads, using the same practice cache tag as JSON/HTML/Markdown. Writes purge all representations; static templates do not contribute stale ETags to rendered documents.
- Publish OpenAPI, API docs, RFC 9727 API catalog, auth guidance, a hashed real read skill, and a draft ARD manifest. Feature-detect read-only WebMCP search for compatible browsers.
- Permit public indexing and answer retrieval while retaining the training opt-out. Keep dashboard/404/JSON representations noindex and exclude dashboard and `/cdn-cgi/` from robots. No credentials are required for public reads.
- Keep CSS/JS/images and static discovery assets free. The explicit Worker-first document routes are a deliberate billing tradeoff for live rendering and content negotiation. The default entrypoint cache remains disabled.

## Deployment guidance

- **Review the target environment before changing access.** Inspect the applicable account and zone controls and confirm changes with the owner. Keep existing crawler and client restrictions in place when improving public retrieval.
- **Keep exceptions narrow.** Limit exceptions to the intended hostname, public read methods, and affected paths. Exclude dashboard and `/cdn-cgi/`, preserve terminating blocks before exemptions, and skip only the mitigation responsible for a confirmed false positive. Use non-interactive controls for APIs rather than browser challenge pages.
- **Validate crawler identification.** Use supported Bot Management fields and current evidence from the target environment. Do not infer identities from generic detection labels, shared fingerprints, or an entire AI Crawler category. Keep deployment-specific detection selections and non-public mappings out of public examples.
- **Align robots and edge policy.** Check the actual merged `/robots.txt`, response headers, and HTML metadata against the published `search=yes, ai-input=yes, ai-train=no` policy. Review mixed-use crawlers individually; a training opt-out does not imply that all AI retrieval should be blocked. Preserve dashboard exclusions and anonymous public reads.
- **Protect writes and representation caching.** Configure Cloudflare Access for dashboard routes and retain JWT validation in the Worker. Ensure cache rules preserve distinct HTML/Markdown variants and that writes invalidate every practice representation.
- **Validate configuration and live behavior separately.** Dry-run each proposed Rulesets mutation before applying the reviewed payload. A successful dry run validates configuration, not traffic matches. Check permitted reads, retained restrictions, and dashboard protection afterward; synthetic probes do not prove a crawler's operator identity.
- **Verify HTTPS and discovery.** Check redirects, production canonicals, sitemap reachability, and native Markdown negotiation. Application-authored Markdown does not require an edge HTML-to-Markdown converter. Review optional discovery features, such as Crawler Hints, for the target deployment.

## Verification and release

Automated checks cover quality-value negotiation, HTML/Markdown parity, server rendering, escaping and JSON-LD safety, long code fences, source dates, sitemap URLs, discovery manifests and skill digest, HEAD/CORS, rate limiting, write-followed-by-read consistency, and the existing API/auth/schema behavior. Run:

```bash
npm test -- --run
npm run typecheck
npx wrangler deploy --dry-run
```

Local verification passed **46 tests**, TypeScript checking, and the deployment dry run. Browser/HTTP checks against the seeded snapshot confirmed **106 practices** in the initial HTML and Markdown, **108 sitemap URLs**, correct negotiated MIME types, and a working read-only WebMCP search registration. A 390 px practice-page viewport had no horizontal overflow. The local homepage trace measured LCP 106 ms and CLS 0.00; local timings are not comparable to production network timings.

The local practice-page Lighthouse audit scored accessibility 100, best practices 100, and SEO 92. Its only failure was a localhost canonical mismatch: Wrangler rewrites the Link header to the dev origin, while the HTML retains the correct production canonical. Verify agreement on the deployed hostname. The unsupported optional `Agentmap` robots directive was removed; capability discovery uses the well-known manifest and HTML link instead.

### Production deployment — 2026-10-15

The application was deployed successfully with **`npx wrangler deploy`**. The final pre-deployment run passed all **46 tests**, type checking, the Wrangler deployment dry run, and formatting/diff checks.

Live verification confirmed:

- Homepage and `/practices/1` return **200 HTML or Markdown**, according to Accept, with `Vary: Accept`, correct production canonicals, and `search=yes, ai-input=yes, ai-train=no`. Public HTML no longer sends noindex.
- Repeated HTML and Markdown requests to `/practices/1` each return **`Cf-Cache-Status: HIT`** with the correct representation, demonstrating independent cached variants.
- Explicit practice Markdown, negotiated API docs, `/llms.txt`, `/llms-full.txt`, and `/sitemap.xml` return the expected MIME types. The sitemap contains **108 canonical URLs**. Public API JSON still sends `X-Robots-Tag: noindex`.
- The merged robots response reports wildcard **`search=yes, ai-input=yes, ai-train=no`**, dashboard and `/cdn-cgi/` exclusions, the sitemap, and the published crawler restrictions; `/api/` is no longer disallowed.
- Access smoke checks confirmed permitted public reads and retained owner-approved restrictions. These checks establish observed request handling, not universal identification of a crawler's operator or disguised traffic.
- Unauthenticated `/dashboard` and `/dashboard/api/practices` still return **302 to Cloudflare Access**.

For subsequent deployments:

1. Fetch homepage and a real practice in HTML and Markdown; confirm Content-Type and Vary on each variant. Repeat to observe independent `Cf-Cache-Status` hits. Add a dashboard practice and verify JSON, HTML, Markdown, sitemap, and agent index are refreshed. Local dev does not emulate Workers Cache.
2. Inspect the actual production `/robots.txt` for managed additions and confirm the published crawler policy and intended indexing behavior. Verify permitted reads, retained owner-approved restrictions, and dashboard protection. Trace any unexpected public noindex directive through both origin responses and edge configuration.
3. Verify HTTPS redirects and consider Crawler Hints in the zone. Submit the sitemap to search consoles and rerun the readiness diagnostics. Observe real crawler errors and AEO citations after content has been recrawled.
4. Advanced OAuth/MCP/A2A, Web Bot Auth, and DNS-AID checks require real services or DNS configuration. This public read repository does not advertise nonexistent authorization servers, MCP servers, agent identities, or commerce protocols. `/auth.md` accurately describes Access-protected contributions.

No live post-deployment readiness score is claimed by this implementation review.

## Sources

- [From ranking to recommended: Cloudflare AEO](https://blog.cloudflare.com/aeo/): distinguish agent diagnostics from actual model citation/mention outcomes.
- [Improve SEO](https://developers.cloudflare.com/fundamentals/performance/improve-seo/index.md): content quality, speed, HTTPS, Crawler Hints, and verified bot access.
- [`/cdn-cgi/` endpoint](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/index.md): managed infrastructure, exclude from robots and scanners. This site does not serve transformed images that require a narrower exception.
- [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/), [scoped Worker-first routes](https://developers.cloudflare.com/workers/static-assets/routing/worker-script/), and [Workers Cache Vary support](https://developers.cloudflare.com/workers/cache/).
- [AI Crawl Control and WAF precedence](https://developers.cloudflare.com/ai-crawl-control/configuration/ai-crawl-control-with-waf/), [per-crawler actions](https://developers.cloudflare.com/ai-crawl-control/features/manage-ai-crawlers/), and [Radar bot metadata](https://radar.cloudflare.com/bots/directory).
- [Bot Preference Sync / managed robots](https://developers.cloudflare.com/bots/additional-configurations/managed-robots-txt/) and [AI behavior policies](https://developers.cloudflare.com/bots/additional-configurations/block-ai-bots/): distinguish Training Disallow from stronger blocking of mixed-purpose crawlers.
- [Bot Management variables](https://developers.cloudflare.com/bots/reference/bot-management-variables/) and [Detection IDs](https://developers.cloudflare.com/bots/additional-configurations/detection-ids/): use Cloudflare-assigned detection fields in expressions and validate mappings through [Security Analytics](https://developers.cloudflare.com/waf/analytics/security-analytics/).
- [Browser Integrity Check](https://developers.cloudflare.com/waf/tools/browser-integrity-check/), [Configuration Rules settings](https://developers.cloudflare.com/rules/configuration-rules/settings/), [Markdown for Agents](https://developers.cloudflare.com/fundamentals/reference/markdown-for-agents/), and [Crawler Hints](https://developers.cloudflare.com/cache/advanced-configuration/crawler-hints/).
- [RFC 9727 API catalogs](https://www.rfc-editor.org/rfc/rfc9727), [RFC 8288 Link headers](https://www.rfc-editor.org/rfc/rfc8288), [Agent Skills Discovery v0.2](https://github.com/cloudflare/agent-skills-discovery-rfc), and [draft ARD guidance](https://isitagentready.com/.well-known/agent-skills/ard/SKILL.md).
