-- Editorial review, fact-checked and applied to production on 2026-10-29.
-- Apply after migrations and copyable-expressions.sql; rehearse twice on an isolated production export.
-- Preserve existing IDs and timestamps on no-op reruns. Evidence/limitations: content-review-2026-10-29.md.
WITH corrections(practice_id, patch) AS (VALUES
	(3, json_object(
		'description', 'Observe expected matches before enforcing a security rule. Choose observation and mitigation actions for the specific product, phase, and plan, then deploy narrowly and monitor outcomes.',
		'prerequisites', 'Request-phase WAF custom-rule and rate-limiting Log actions require Enterprise. The response-WAF announcement describes separate Log/Block availability on all plans; confirm the current rollout, action, field, and quota in the target zone.',
		'notes', 'Dry run validates configuration, not traffic matches. Without the relevant Log action, estimate matches with analytics, use conservative thresholds, and test one host/path first. Managed Challenge is only for interactive browser traffic; APIs need non-interactive controls. Security Events may be sampled. The response phase cannot undo work already performed at the origin.'
	)),
	(32, json_object(
		'prerequisites', 'Enterprise Bot Management for enforcement with cf.bot_management.js_detection.passed; JSD enabled, CSP compatible, and an earlier HTML page to bootstrap browser clients. Review Precursor availability and migration before adding new JSD-only policies.',
		'notes', 'Action: Managed Challenge, not unconditional Block. Choose a post-entrypoint HTML navigation; do not enforce this example on first visits, APIs, native apps, or WebSockets. A failed or absent result can be legitimate. Precursor supersedes JSD with continuous session evaluation; assess it in Monitor mode first. Show Interstitial can challenge clients even in Monitor mode: scope Interstitial Rules and exclude non-browser API traffic. See https://developers.cloudflare.com/cloudflare-challenges/precursor/.'
	)),
	(71, json_object(
		'prerequisites', 'Enterprise Bot Management; JSD enabled; compatible CSP; an earlier HTML page bootstraps clients. Evaluate the newer Precursor session model before extending this JSD-specific example.',
		'notes', 'Use Managed Challenge only on a post-bootstrap browser navigation. User-Agent is a weak, spoofable hint, not proof that JavaScript ran. Exclude first visits and non-browser clients. Precursor supersedes JSD; Monitor does not change bot score or clearance, but enabling Show Interstitial can still challenge clients in either mode. Explicitly scope its Interstitial Rules. See https://developers.cloudflare.com/cloudflare-challenges/precursor/.'
	)),
	(72, json_object(
		'title', 'Rate Limit Browser Sessions with Stable Clearance UUIDs',
		'description', 'Use the stable UUID from a valid Cloudflare clearance cookie for selected browser counters rather than the rotating encrypted cf_clearance cookie value. Protect clients without valid clearance separately.',
		'prerequisites', 'Advanced Rate Limiting entitlement and valid browser clearance on the protected workflow. Confirm supported characteristics, counting expression, period, and action in the target zone.',
		'expression', '(http.host eq "www.example.com" and http.request.uri.path eq "/search" and http.request.method eq "GET")',
		'expressions_configuration_details', 'Illustrative browser match only; choose thresholds from observed traffic. API characteristics: cf.colo.id and http.request.clearance.uuid. Counting expression: (http.host eq "www.example.com" and http.request.uri.path eq "/search" and http.request.method eq "GET" and http.request.clearance.uuid ne ""). Add a separate rule with an appropriate characteristic, such as source IP, for the same endpoint when http.request.clearance.uuid eq "".',
		'source_reference', 'https://developers.cloudflare.com/cloudflare-challenges/concepts/clearance/',
		'notes', 'Clearance is not application authentication. The UUID remains stable when JSD or Precursor refreshes the encrypted cookie value, but attackers can establish new sessions. Retain independent authenticated-user and abuse limits where appropriate. Excluding empty UUIDs from this counter does not protect those requests by itself. Challenge Passage does not universally exempt rate limiting. Use browser challenges only for interactive browser workflows.'
	)),
	(103, json_object(
		'description', 'Learn request field types and constraints for selected operations, review conformance, and explicitly enforce the learned detection with a scoped security rule. Learned profiles are not a complete request allowlist.',
		'expressions_configuration_details', 'Select Learn profile for the chosen operation; discovery and manual operation creation do not start learning automatically. Review Profile Analysis and representative valid/invalid requests. The example matches a learned violation; choose a plan-appropriate observation action before narrow enforcement. Export an approved learned schema and upload it for validation if you need a fixed contract.',
		'source_reference', 'https://developers.cloudflare.com/waf/detections/application-profiles/schema-profiles/',
		'notes', 'Successful learning traffic may contain bots, scanners, or malicious requests. Profiles can change on weekly/manual relearning; monitor drift. Required parameter presence and repeated-parameter uniqueness are not enforced; new parameters alone do not cause violations. Constraints cover learned fields, not a full allowlist. Multipart forms, GraphQL, and XML are unsupported. Operations without a profile are not classified; learning/detection is not automatic blocking. Availability remains API Security access or invited Enterprise closed beta.'
	))
)
UPDATE BestPractices AS bp
SET title = CASE WHEN json_type(c.patch, '$.title') IS NULL THEN bp.title ELSE json_extract(c.patch, '$.title') END,
	description = CASE WHEN json_type(c.patch, '$.description') IS NULL THEN bp.description ELSE json_extract(c.patch, '$.description') END,
	prerequisites = CASE WHEN json_type(c.patch, '$.prerequisites') IS NULL THEN bp.prerequisites ELSE json_extract(c.patch, '$.prerequisites') END,
	expression = CASE WHEN json_type(c.patch, '$.expression') IS NULL THEN bp.expression ELSE json_extract(c.patch, '$.expression') END,
	expressions_configuration_details = CASE WHEN json_type(c.patch, '$.expressions_configuration_details') IS NULL THEN bp.expressions_configuration_details ELSE json_extract(c.patch, '$.expressions_configuration_details') END,
	source_reference = CASE WHEN json_type(c.patch, '$.source_reference') IS NULL THEN bp.source_reference ELSE json_extract(c.patch, '$.source_reference') END,
	notes = CASE WHEN json_type(c.patch, '$.notes') IS NULL THEN bp.notes ELSE json_extract(c.patch, '$.notes') END,
	updated_at = CURRENT_TIMESTAMP
FROM corrections AS c
WHERE bp.practice_id = c.practice_id
	AND EXISTS (
		SELECT 1 FROM json_each(c.patch) AS item
		WHERE item.value IS NOT CASE item.key
			WHEN 'title' THEN bp.title WHEN 'description' THEN bp.description
			WHEN 'prerequisites' THEN bp.prerequisites WHEN 'expression' THEN bp.expression
			WHEN 'expressions_configuration_details' THEN bp.expressions_configuration_details
			WHEN 'source_reference' THEN bp.source_reference WHEN 'notes' THEN bp.notes
		END
	);

INSERT INTO Categories (name, description, display_order)
SELECT 'Load Balancing', 'Application health checks, traffic steering, and tested failover.', 19
WHERE NOT EXISTS (SELECT 1 FROM Categories WHERE name = 'Load Balancing');
INSERT INTO CloudflareFeatures (name, feature_url, subscription_level)
SELECT 'Load Balancing', 'https://developers.cloudflare.com/load-balancing/', 'Paid Add-On'
WHERE NOT EXISTS (SELECT 1 FROM CloudflareFeatures WHERE name = 'Load Balancing');

-- Configuration guidance, not paste-ready response-phase expressions: field/phase references remain unverified.
WITH additions(title, description, domain, category, feature, level, impact, difficulty, prerequisites, guidance, source, notes) AS (VALUES
	('Review Full-Transaction WAF Protection',
	 'Review request and response evidence together when evaluating exploit attempts, and assess the response-side managed protections available in your zone.',
	 'Security', 'WAF Managed Rules', 'WAF', 'Recommended', 'High', 'Medium',
	 'Announcement-based guidance from 2026-10-21. Full-transaction WAF was announced for all plans; managed rulesets, individual rules, rollout, and contract entitlements still need target-zone verification.',
	 'Inventory available response-aware managed protections and actions. Test harmless representative success, error, and disclosure cases in staging. Review evidence and false positives before changing enforcement; retain request-side prevention and origin fixes.',
	 'https://blog.cloudflare.com/full-transaction-waf/',
	 'Response evidence can help distinguish an attempted attack from an apparent outcome, but it is not proof that every exploit succeeded or failed. Response blocking cannot reverse database writes, outbound calls, or other origin-side effects. Executable response-signature fields and phase configuration are intentionally omitted pending authoritative reference and entitlement verification.'),
	('Contain Disclosures with Scoped Custom Response Rules',
	 'Where available, use response-side security rules to contain selected disclosures or unsafe responses while fixing their origin cause.',
	 'Security', 'WAF Custom Rules', 'WAF', 'Situational', 'High', 'Medium',
	 'The full-transaction WAF announcement describes up to three custom response rules on all plans with Log and Block. Confirm current rollout, quota, supported fields, and actions in the target zone before deployment.',
	 'Start with observation of a narrow hostname and operation, validate ordinary errors and permitted clients, then block only confirmed unwanted responses. Review rollback and request-side prevention. This is not the custom error body returned by a request-phase Block action.',
	 'https://blog.cloudflare.com/full-transaction-waf/',
	 'Announcement-only configuration guidance: no paste-ready expression or phase name is supplied. Arbitrary custom response-body matching is not available according to the announcement. Do not infer request-phase Log entitlements from response-rule availability. A client-supplied internal-user header is not identity; require a verified assertion protected from spoofing. Blocking a response does not undo an origin-side transaction.'),
	('Roll Out Precursor with Explicit Browser Scope',
	 'Evaluate continuous browser session signals in Monitor mode before arming their effect on bot score and clearance, while independently controlling interstitial challenges.',
	 'Security', 'Bot Management', 'Bot Management', 'Situational', 'High', 'Medium',
	 'Confirm Precursor availability for the zone, compatible client-side script/CSP behavior, and an inventory of browser, API, native-app, and server-to-server traffic.',
	 'Start with Status Monitor and Show Interstitial off. Use Interstitial Rules to enable it only on selected sensitive browser pages, or explicitly exclude API hosts/paths if using a sitewide default. Test first visits, cookie-less requests, browser fetch calls, accessibility, and rollback before Status Arm.',
	 'https://developers.cloudflare.com/cloudflare-challenges/precursor/',
	 'Monitor does not affect bot score or challenge clearance, but Show Interstitial can still challenge traffic in either Monitor or Armed mode. Armed detections can affect bot score and invalidate clearance before nominal expiry. Precursor supersedes JSD; migrate deliberately rather than layering blanket JSD rules. Turning off an API interstitial does not disable browser session evaluation. Clearance is not login authorization.'),
	('Investigate Attack Signatures Before Scoped Mitigation',
	 'Use request attack-signature detections as investigation signals and validate confidence, category, and signature references before enforcing a narrow rule.',
	 'Security', 'WAF Custom Rules', 'WAF', 'Situational', 'High', 'Medium',
	 'Attack Signature Detection is documented as Early Access. Confirm enrollment, detector enablement, field access, and the chosen action for the target plan.',
	 'Review detections and representative legitimate requests in Security Analytics. Select documented request signature fields for a specific operation and validate configuration before observation and enforcement. Preserve a rollback version and inspect detector failures separately.',
	 'https://developers.cloudflare.com/waf/detections/attack-signature-detection/use-attack-signatures-in-security-rules/',
	 'Detection does not itself mitigate. A signature match or absence is not proof of exploit outcome or comprehensive inspection. Do not conflate Early Access request-signature fields with newly announced response-signature fields. Avoid blocking broad categories without traffic review; use non-interactive controls for APIs.'),
	('Define Request Inspection Coverage and Oversize Policy',
	 'Distinguish accepted upload sizes from inspected body sizes, and explicitly handle content that detectors cannot fully inspect on each sensitive endpoint.',
	 'Security', 'WAF Managed Rules', 'WAF', 'Recommended', 'High', 'Medium',
	 'Inventory managed/custom inspection limits and detector entitlements for the plan. http.request.body.truncated requires Enterprise; do not assume the upload-size limit equals the inspection limit.',
	 'Document permitted payload types and sizes, then test at and beyond the actual inspection boundary. Where entitled, observe truncation and reported detector failures. For sensitive workflows choose an explicit reject, quarantine, alternate inspection, or accepted-risk policy; enforce independent limits at the application.',
	 'https://developers.cloudflare.com/waf/managed-rules/',
	 'A truncated inspection does not truncate what the origin receives. Empty cf.appsec.request.failed_detections means no failures were reported, not that every detector ran or all bytes were inspected. Cross-check the large-body, malicious-upload, and detection-failure recommendations rather than treating large payloads as inherently malicious. Do not impose browser challenges on upload APIs.'),
	('Align URL Normalization with Origin and Cache Semantics',
	 'Test consistent URL interpretation across security rules, cache keys, rewrites, and the origin before changing normalization or dropping query parameters.',
	 'Security', 'Performance', 'CDN (Caching)', 'Recommended', 'High', 'Medium',
	 'Inventory incoming/origin normalization settings, application routing, signatures, and any plan-specific custom cache-key entitlement.',
	 'Test encoded separators, repeated slashes, path case, signed URLs, and meaningful queries. When URL normalization is enabled, assess Normalize URLs to origin, especially with custom cache keys, so the cached URL agrees with the origin interpretation. Preserve distinctions that change the representation.',
	 'https://developers.cloudflare.com/cache/how-to/cache-rules/settings/',
	 'Do not lowercase case-sensitive paths, decode repeatedly, or remove authentication/signature parameters indiscriminately. Cache normalization must not merge different users, resources, or negotiated representations. Stage changes and keep rollback settings; a higher hit rate is not evidence of correct isolation.'),
	('Keep Authenticated and Personalized Responses Out of Shared Cache',
	 'Explicitly separate private application responses from public cacheable content and verify that shared caches cannot serve one user another user''s data.',
	 'Security', 'Performance', 'CDN (Caching)', 'Recommended', 'High', 'Medium',
	 'An inventory of authentication/session cookies, Authorization use, personalized routes, and all origin/edge cache overrides. Verify Cache Rules and Cache Deception Armor availability for the plan.',
	 'Bypass shared caching for login, account, dashboard, and personalized API responses. Preserve appropriate private/no-store origin directives rather than overriding them with broad cache eligibility. Test anonymously and with two different users, including extension-like paths and query variants. Purge any previously cached private responses after correcting policy.',
	 'https://developers.cloudflare.com/cache/how-to/cache-rules/settings/',
	 'Authorization or Set-Cookie alone is not a universal guarantee when cache overrides are present. Cache Deception Armor supplements rather than replaces route/authentication-aware cache policy. Verify actual response headers and cache behavior, including Workers-managed caching. Do not put credentials or user IDs into publicly visible cache keys.'),
	('Set Separate Browser and Edge Freshness Policies',
	 'Choose freshness, revalidation, and invalidation policies for public documents and versioned assets separately at browser and edge layers.',
	 'Performance', 'Performance', 'CDN (Caching)', 'Recommended', 'Medium', 'Medium',
	 'Identify the responsible cache product, resource ownership, acceptable staleness, query/negotiation variants, and available purge mechanisms.',
	 'Give content-hashed immutable assets long browser lifetimes only when new releases use new URLs. Use shorter freshness or revalidation for changing documents. Specify edge policy independently where supported. Verify a content update, variant separation, failed-purge behavior, and rollbacks with real cache hits.',
	 'https://developers.cloudflare.com/cache/concepts/cache-control/',
	 'Purging the edge does not clear browser caches. stale-while-revalidate can extend served staleness beyond max-age. Preserve required query and Vary distinctions; do not cache error, private, or authenticated responses merely to improve hit ratio. CDN Cache Rules and Workers Cache have different configuration and purge scopes.'),
	('Monitor Application Readiness with Load Balancer Health Checks',
	 'Use health checks that verify the application can serve its intended workload instead of treating an open port or generic HTTP response as readiness.',
	 'Reliability', 'Load Balancing', 'Load Balancing', 'Recommended', 'High', 'Medium',
	 'Cloudflare Load Balancing subscription, redundant endpoints, a safe readiness path, correct monitor Host/TLS settings, and monitor reachability through origin controls. Protocols and intervals depend on plan.',
	 'Configure HTTPS monitoring with expected response codes and, where useful, a stable readiness substring within the inspected response prefix. Set timeouts, retries, check regions, and pool health thresholds from recovery objectives and origin load. Test a failed dependency as well as a stopped server.',
	 'https://developers.cloudflare.com/load-balancing/monitors/create-monitor/',
	 'Do not accept a login redirect or generic error page as healthy unless intentionally required. Monitor responses must not expose secrets or require bypassing origin authentication broadly. Use a safe read-only check; do not perform mutations. Faster checking increases probe load and does not promise instantaneous failover.'),
	('Rehearse Load Balancer Failover and Fallback Recovery',
	 'Exercise endpoint, pool, and regional failure and recovery, including the last-resort fallback path, before relying on load balancing during an outage.',
	 'Reliability', 'Load Balancing', 'Load Balancing', 'Recommended', 'High', 'Complex',
	 'Load Balancing subscription, multiple usable endpoints/pools, approved drill scope, backups, application-state replication, and a rollback owner. Steering and adaptive-routing options require their own entitlement.',
	 'In staging or an approved drill, fail one endpoint, then a pool, then all normal pools. Measure observed failover/recovery, inspect fallback analytics, verify session affinity and application state, and restore normal steering. Maintain a usable fallback or controlled maintenance response.',
	 'https://developers.cloudflare.com/load-balancing/understand-basics/health-details/',
	 'The fallback pool ignores health and is a last resort, not a guaranteed healthy target. Load balancing does not replicate sessions or database state. Account for DNS caching where applicable and connection/session behavior. Never perform an unapproved production failure drill.'),
	('Deploy HSTS Gradually with a Recovery Plan',
	 'Enable persistent HTTPS enforcement only after confirming reliable TLS for every covered hostname and understanding the browser-policy recovery window.',
	 'Security', 'SSL/TLS', 'SSL/TLS', 'Recommended', 'High', 'Medium',
	 'Working HTTPS, valid edge/origin TLS as appropriate, complete hostname/subdomain inventory, and an owner for certificate renewal and recovery.',
	 'Verify HTTPS and redirects first. Start with a deliberately chosen supported max-age and increase after observation. Enable includeSubDomains only when all covered subdomains support HTTPS. Treat preload as a separate deliberate commitment with browser-list submission/removal procedures.',
	 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/',
	 'Turning off a dashboard setting does not erase policies already stored in browsers. Removing HTTPS before cached HSTS expires can make the site inaccessible. Preload recovery depends on browser-list updates, not an immediate edge rollback; do not preload an incompletely inventoried domain.'),
	('Measure Modern Compression with Compatible Fallbacks',
	 'Evaluate compression for eligible text and application responses using measured transfer size and latency while preserving compatibility and response correctness.',
	 'Performance', 'Performance', 'Rules', 'Recommended', 'Medium', 'Easy',
	 'Compression Rules available in the zone, compressible content types, and representative clients with and without Zstandard/Brotli support.',
	 'Review default compression before adding an override. Where appropriate, use the documented Zstandard, Brotli, Gzip preference with supported fallback; compare response size, Content-Encoding, and latency for each client class. Verify caches and body-modifying features still produce correct responses.',
	 'https://developers.cloudflare.com/rules/compression-rules/examples/enable-zstandard/',
	 'Do not assume every response is compressible or force an encoding unsupported by the client. Already-compressed assets may not benefit. Consider application-level compression side channels where secrets and attacker-controlled input share a response. Keep a rollback rule and avoid claiming an unmeasured universal performance gain.'),
	('Connect Asset Discovery to Human-Approved Security Changes',
	 'Use an operational loop from application inventory through runtime detections and investigation to reviewed mitigation, without treating a new signal as an automatic blocking decision.',
	 'General', 'Automation & Management', 'Fundamentals', 'Recommended', 'Medium', 'Medium',
	 'Named application owners, a trusted asset/operation inventory, entitled telemetry sources, and a change/rollback approval process. Announced or developing capabilities are not assumed deployed.',
	 'Regularly reconcile public hosts and operations, profile coverage, detection enablement, and bypasses. Triage new signals with application owners, reproduce safely, and approve narrowly scoped changes with measurable outcomes and a rollback version.',
	 'https://blog.cloudflare.com/ai-era-framework/',
	 'The framework is operational guidance, not an entitlement or implementation contract. Keep secrets and raw sensitive telemetry out of public repositories and AI prompts. Distinguish available features from Early Access and roadmap claims, and do not authorize autonomous security mutations solely from detector output.')
)
INSERT INTO BestPractices (
	title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level,
	prerequisites, expressions_configuration_details, source_reference, notes
)
SELECT a.title, a.description, a.domain, c.category_id, f.feature_id, a.level, a.impact, a.difficulty,
	a.prerequisites, a.guidance, a.source, a.notes
FROM additions a
JOIN Categories c ON c.name = a.category
JOIN CloudflareFeatures f ON f.name = a.feature
WHERE NOT EXISTS (SELECT 1 FROM BestPractices bp WHERE bp.title = a.title);
