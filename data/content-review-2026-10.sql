-- Content review, October 2026 (applied to production on 2026-10-04, after migration 0003)
--
-- Sources: davidtofan.com/articles/cloudflare-l7-security-recommendations (canonical article), Birthday Week 2026,
-- Rules language fields/functions reference, and the Rate Limiting Rules best practices.
--
-- Apply:   npx wrangler d1 execute DB --local  --file=./data/content-review-2026-10.sql
--          npx wrangler d1 execute DB --remote --file=./data/content-review-2026-10.sql
-- Safe to re-run: updates are deterministic and inserts are skipped when the title already exists.
-- Not included (needs an editorial decision): removing duplicate #1 (same as #64), filling 36 NULL impact levels.

PRAGMA defer_foreign_keys = true;

-- =====================================================================================================
-- 1. Taxonomy
-- =====================================================================================================

-- Page Shield is now "Client-side security"; script monitoring is available on all plans
UPDATE CloudflareFeatures
SET name = 'Client-side security', feature_url = 'https://developers.cloudflare.com/client-side-security/', subscription_level = 'Free'
WHERE feature_id = 7;

-- Logpush is available to Free, Pro, and Business through pay-as-you-go pricing (Birthday Week 2026)
UPDATE CloudflareFeatures SET subscription_level = 'Paid Add-On' WHERE feature_id = 11;

-- Moved docs URL
UPDATE CloudflareFeatures
SET feature_url = 'https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/'
WHERE feature_id = 9;

INSERT OR IGNORE INTO Categories (name, description, display_order) VALUES
('AI Security', 'Protecting LLM-powered applications against prompt injection, PII exposure, and unsafe content.', 18);

INSERT OR IGNORE INTO CloudflareFeatures (name, feature_url, subscription_level) VALUES
('AI Security for Apps', 'https://developers.cloudflare.com/waf/detections/ai-security-for-apps/', 'Paid Add-On'),
('AI Crawl Control', 'https://developers.cloudflare.com/ai-crawl-control/', 'Free'),
('Threat Intelligence', 'https://developers.cloudflare.com/waf/detections/threat-intelligence/', 'Paid Add-On'),
('Malicious Uploads Detection', 'https://developers.cloudflare.com/waf/detections/malicious-uploads/', 'Paid Add-On');

-- =====================================================================================================
-- 2. Global corrections
-- =====================================================================================================

-- ip.geoip.* fields are deprecated in favor of ip.src.* (same values)
UPDATE BestPractices
SET expressions_configuration_details = REPLACE(REPLACE(REPLACE(expressions_configuration_details,
		'ip.geoip.country', 'ip.src.country'), 'ip.geoip.asnum', 'ip.src.asnum'), 'ip.geoip.continent', 'ip.src.continent'),
	updated_at = CURRENT_TIMESTAMP
WHERE expressions_configuration_details LIKE '%ip.geoip.%';

-- Consistent example hostname
UPDATE BestPractices
SET expressions_configuration_details = REPLACE(expressions_configuration_details, 'www.cf-testing.com', 'www.example.com'),
	updated_at = CURRENT_TIMESTAMP
WHERE expressions_configuration_details LIKE '%www.cf-testing.com%';

-- Documentation URLs that now redirect (301) to a new location
UPDATE BestPractices SET source_reference = 'https://developers.cloudflare.com/fundamentals/user-profiles/2fa/', updated_at = CURRENT_TIMESTAMP
WHERE source_reference = 'https://developers.cloudflare.com/fundamentals/account/account-security/2fa/';
UPDATE BestPractices SET source_reference = 'https://developers.cloudflare.com/fundamentals/manage-members/', updated_at = CURRENT_TIMESTAMP
WHERE source_reference = 'https://developers.cloudflare.com/fundamentals/setup/manage-members/';
UPDATE BestPractices SET source_reference = 'https://developers.cloudflare.com/fundamentals/manage-members/dashboard-sso/', updated_at = CURRENT_TIMESTAMP
WHERE source_reference = 'https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/dash-sso-apps/';
UPDATE BestPractices SET source_reference = 'https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/', updated_at = CURRENT_TIMESTAMP
WHERE source_reference = 'https://developers.cloudflare.com/turnstile/tutorials/implicit-vs-explicit-rendering/';
UPDATE BestPractices SET source_reference = 'https://developers.cloudflare.com/ddos-protection/best-practices/proactive-defense/', updated_at = CURRENT_TIMESTAMP
WHERE source_reference = 'https://developers.cloudflare.com/ddos-protection/best-practices/respond-to-ddos-attacks/';
UPDATE BestPractices SET source_reference = 'https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/', updated_at = CURRENT_TIMESTAMP
WHERE source_reference = 'https://developers.cloudflare.com/fundamentals/setup/account/account-security/review-audit-logs/';
UPDATE BestPractices SET source_reference = 'https://developers.cloudflare.com/logs/logpush/', updated_at = CURRENT_TIMESTAMP
WHERE source_reference = 'https://developers.cloudflare.com/logs/about/';
UPDATE BestPractices SET source_reference = 'https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/', updated_at = CURRENT_TIMESTAMP
WHERE source_reference = 'https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/';
UPDATE BestPractices SET source_reference = 'https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/challenge-passage/', updated_at = CURRENT_TIMESTAMP
WHERE source_reference = 'https://developers.cloudflare.com/fundamentals/security/cloudflare-challenges/challenge-passage/';
UPDATE BestPractices SET source_reference = 'https://developers.cloudflare.com/changelog/post/2025-06-09-transform-rule-subrequest-matching/', updated_at = CURRENT_TIMESTAMP
WHERE source_reference = 'https://developers.cloudflare.com/changelog/2025-06-09-transform-rule-subrequest-matching/';

-- Redirecting URLs embedded in free text
UPDATE BestPractices
SET notes = REPLACE(REPLACE(REPLACE(notes,
		'https://developers.cloudflare.com/page-shield/detection/monitor-connections-scripts/', 'https://developers.cloudflare.com/client-side-security/detection/monitor-connections-scripts/'),
		'https://developers.cloudflare.com/page-shield/', 'https://developers.cloudflare.com/client-side-security/'),
		'https://developers.cloudflare.com/logs/about/', 'https://developers.cloudflare.com/logs/logpush/'),
	updated_at = CURRENT_TIMESTAMP
WHERE notes LIKE '%developers.cloudflare.com/page-shield/%' OR notes LIKE '%developers.cloudflare.com/logs/about/%';

-- =====================================================================================================
-- 3. Updates to existing practices (aligned with the current article and docs)
-- =====================================================================================================

-- #14: skipping every verified bot now also skips AI crawlers; skip only the categories you rely on
UPDATE BestPractices SET
	expressions_configuration_details = '(cf.verified_bot_category in {"Search Engine Crawler" "Search Engine Optimization" "Monitoring & Analytics" "Academic Research" "Security" "Accessibility" "Webhooks" "Feed Fetcher" "Archiver"})',
	notes = 'Place this rule first. AI crawlers are verified bots too, so skip only the verified bot categories you rely on and manage AI crawlers with AI Crawl Control. cf.verified_bot_category is available on all plans. You might also want to allow sitemap.xml, robots.txt, or RSS feeds to everyone.',
	source_reference = 'https://developers.cloudflare.com/bots/concepts/bot/verified-bots/',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 14;

-- #15: do not embed secrets (API keys) in rule expressions
UPDATE BestPractices SET
	expressions_configuration_details = '(http.host eq "api.example.com" and starts_with(http.request.uri.path, "/api/resources") and http.request.method eq "GET" and cf.waf.score gt 70 and cf.bot_management.score lt 10 and any(http.request.headers["x-api-shield"][*] eq "DEMO"))',
	notes = 'Be as specific as possible and never embed secrets (API keys, tokens) in rule expressions. The ultimate goal should be a positive security model with API Shield (Schema Validation, JWT Validation).',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 15;

-- #19: clean expression; current availability and rollout guidance
UPDATE BestPractices SET
	expressions_configuration_details = '(cf.waf.score lt 20)',
	notes = 'Start with Log, review Security Events, then use Managed Challenge or Block. Cloudflare''s own adaptive AI testing (Birthday Week 2026) ran Attack Score blocking scores of 30 or below. Business plans can use cf.waf.score.class (for example, "attack"); per Birthday Week 2026, Attack Score is being made available to all customers.',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 19;

-- #23: replace the "..." placeholder with the full example list
UPDATE BestPractices SET
	expressions_configuration_details = '(ip.src.country in {"AF" "BY" "CF" "CG" "CD" "CI" "CU" "ET" "IR" "IQ" "KP" "LR" "ML" "MM" "SO" "SS" "SD" "SY" "VE" "YE" "ZW" "ER"})',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 23;

-- #24: case-insensitive matching and common scripting clients
UPDATE BestPractices SET
	expressions_configuration_details = '(lower(http.user_agent) contains "python" or lower(http.user_agent) contains "go-http-client" or lower(http.user_agent) contains "scrapy" or lower(http.user_agent) contains "libwww-perl" or lower(http.user_agent) contains "fasthttp" or lower(http.user_agent) contains "undici" or lower(http.user_agent) contains "curl" or lower(http.user_agent) contains "wget" or http.user_agent eq "")',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 24;

-- #25: include wp-login.php and keep admin-ajax.php reachable
UPDATE BestPractices SET
	expressions_configuration_details = '((starts_with(http.request.uri.path, "/wp-admin") or http.request.uri.path eq "/wp-login.php") and not http.request.uri.path eq "/wp-admin/admin-ajax.php" and not ip.src in $allowed_ips)',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 25;

-- #31, #32: exclude verified bots and static resources from bot rules
UPDATE BestPractices SET
	expressions_configuration_details = '(cf.bot_management.score lt 30 and not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 31;

UPDATE BestPractices SET
	expressions_configuration_details = '(http.request.uri.path eq "/critical/path" and not cf.bot_management.js_detection.passed and not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 32;

-- #34: scope to the login endpoint and method
UPDATE BestPractices SET
	expressions_configuration_details = '(http.host eq "www.example.com" and starts_with(http.request.uri.path, "/login") and http.request.method in {"POST"} and any(cf.bot_management.detection_ids[*] in {201326592}))',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 34;

-- #36: mention the more precise username+password pair check
UPDATE BestPractices SET
	notes = COALESCE(notes || ' ', '') || 'cf.waf.credential_check.username_and_password_leaked (Pro or above) matches only leaked username-password pairs and reduces false positives.',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 36 AND COALESCE(notes, '') NOT LIKE '%username_and_password_leaked%';

-- #48: Page Shield is now Client-side security
UPDATE BestPractices SET
	title = 'Monitor Client-side Scripts with Client-side Security',
	description = 'Use Client-side security (formerly Page Shield) to monitor the scripts, connections, and cookies loaded by your pages and get alerted to changes or malicious resources.',
	expressions_configuration_details = 'Enable Client-side security monitoring and configure alerts in Notifications.',
	notes = 'Script monitoring is available on all plans; connection and cookie monitoring and alerts require Business or above. Malicious script detection and content security rules (positive security model, PCI DSS v4.0 requirement 6.4.3) require Client-Side Security Advanced (formerly the Page Shield add-on).',
	source_reference = 'https://developers.cloudflare.com/client-side-security/',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 48;

-- #56: Logpush is no longer Enterprise-only
UPDATE BestPractices SET
	notes = 'Logpush is strongly recommended for long-term storage and non-sampled logs. Since Birthday Week 2026 it is available on all plans (pay-as-you-go), including Logpush Transformers to filter, redact, and reformat logs with SQL before delivery.',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 56;

-- #67: Transform Rules belong to the Rules feature
UPDATE BestPractices SET feature_id = 19, updated_at = CURRENT_TIMESTAMP WHERE practice_id = 67 AND feature_id <> 19;

-- =====================================================================================================
-- 4. New practices
-- =====================================================================================================

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Block Access to Sensitive Files and Paths',
	'Block requests for configuration files, version control metadata, backups, and debugging endpoints that should never be publicly reachable.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'WAF Custom Rules'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'WAF'),
	'Recommended', 'High', 'Easy', NULL,
	'((http.request.uri.path contains "/.git" or http.request.uri.path contains "/.svn" or http.request.uri.path contains "/.env" or http.request.uri.path contains "/.htaccess" or http.request.uri.path contains "/.htpasswd" or http.request.uri.path contains "/.DS_Store" or ends_with(http.request.uri.path, ".sql") or ends_with(http.request.uri.path, ".bak") or ends_with(http.request.uri.path, ".old") or http.request.uri.path in {"/wp-config.php" "/phpinfo.php"}) and not starts_with(http.request.uri.path, "/.well-known/"))',
	'https://developers.cloudflare.com/waf/custom-rules/use-cases/',
	'Keep /.well-known/ reachable (ACME HTTP validation, security.txt). Adjust the list to your stack; the real fix is to not have these files on the origin at all.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Block Access to Sensitive Files and Paths');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Validate Rule Changes with Dry Run',
	'Validate WAF and Rate Limiting rule changes before publishing them by appending dry_run=true to Rulesets API write requests.',
	'General', (SELECT category_id FROM Categories WHERE name = 'Automation & Management'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Cloudflare API'),
	'Recommended', 'Medium', 'Easy', 'API token with the same permission as the real change (for example, Zone > WAF > Edit).',
	'curl "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint?dry_run=true" --request PUT --header "Authorization: Bearer $CLOUDFLARE_API_TOKEN" --header "Content-Type: application/json" --data ''{"rules":[{"description":"Dry-run validation example","expression":"(http.request.uri.path ne \"/robots.txt\" and cf.bot_management.verified_bot)","action":"log","enabled":true}]}''',
	'https://developers.cloudflare.com/ruleset-engine/rulesets-api/',
	'A valid request returns 200 with "result": null (nothing is saved); an invalid one returns the same error the real write would. Validation covers expression syntax, field/function availability, actions, phase compatibility, permissions, plan entitlements, and quotas. Ideal for CI pipelines (Terraform, scripts).'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Validate Rule Changes with Dry Run');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Roll Out New Blocking Rules Gradually',
	'Apply a new blocking rule to a small share of clients first with the hash_in_range() function, then increase the share while monitoring Security Events.',
	'General', (SELECT category_id FROM Categories WHERE name = 'WAF Custom Rules'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'WAF'),
	'Optional', 'Medium', 'Medium', 'Rule validated with the Log action first.',
	'(hash_in_range(0, 100, ip.src) lt 10 and <your rule condition>)',
	'https://developers.cloudflare.com/ruleset-engine/rules-language/functions/',
	'Seeding with ip.src keeps each client consistently in or out of the rollout; use cf.random_seed to sample individual requests instead. Raise the upper bound (10, 25, 50, 100) as confidence grows. Available on all plans.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Roll Out New Blocking Rules Gradually');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Rate Limit OTP, Verification and Password Reset Endpoints',
	'Rate limit failed attempts on one-time password (OTP), email/SMS verification, and password reset endpoints, which are brute-forced like logins but frequently forgotten.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'Rate Limiting'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Rate Limiting Rules'),
	'Recommended', 'High', 'Easy', NULL,
	'Expression: (http.host eq "www.example.com" and http.request.uri.path in {"/api/otp/validate" "/account/verify" "/password-reset"} and http.request.method eq "POST"). Characteristics: IP. Counting expression: (http.request.uri.path in {"/api/otp/validate" "/account/verify" "/password-reset"} and http.request.method eq "POST" and http.response.code in {401 403}). Rate: 5 requests / 1 minute. Action: Block for 10 minutes.',
	'https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/#protect-otp-and-verification-endpoints',
	'Counting only failed attempts never affects users submitting a valid code. If the endpoint returns 200 for both valid and invalid codes, drop the response code condition and use a lower request-based threshold.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Rate Limit OTP, Verification and Password Reset Endpoints');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Rate Limit Clients Generating Errors',
	'Challenge clients that produce a high volume of 403 or 404 responses, which usually indicates scanners, scrapers, or fuzzers enumerating paths.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'Rate Limiting'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Rate Limiting Rules'),
	'Situational', 'Medium', 'Medium', NULL,
	'Expression: (http.host eq "www.example.com" and not cf.bot_management.verified_bot). Characteristics: IP. Counting expression: (http.host eq "www.example.com" and not cf.bot_management.verified_bot and http.response.code in {403 404}). Rate: more than 20 errors / 1 minute. Action: Managed Challenge.',
	'https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/#limit-requests-from-bots',
	'Because the counting expression uses a response field, matching requests bypass the cache. On static-heavy hostnames, narrow the rule expression (for example, not starts_with(http.request.uri.path, "/assets/") or not cf.bot_management.static_resource). Single-page applications and sites with many broken links generate legitimate 404s; tune the threshold.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Rate Limit Clients Generating Errors');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Rate Limit API Clients by Key or Token',
	'For authenticated APIs, rate limit per API key, bearer token, or session instead of per IP, since one key may be used from many IPs and many keys from one IP.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'Rate Limiting'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Rate Limiting Rules'),
	'Recommended', 'High', 'Medium', 'Advanced Rate Limiting (header-based counting characteristics).',
	'Expression: (http.host eq "api.example.com" and starts_with(http.request.uri.path, "/v1/") and len(http.request.headers["x-api-key"]) gt 0). Characteristics: Header value of x-api-key (or authorization).',
	'https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/#protecting-rest-apis',
	'Header names must be lowercase when used via the API. Requests without the header fall into their own counter, so handle unauthenticated requests with a separate IP-based rule. The identifier can also be a cookie, query parameter, JSON body field, or JWT claim. Use API Discovery or the request rate analysis to choose thresholds.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Rate Limit API Clients by Key or Token');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Rate Limit Content Scraping per Operation',
	'Limit how often a client can perform a specific operation (for example, price lookups) to stop scraping by bots that evade other detections.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'Rate Limiting'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Rate Limiting Rules'),
	'Situational', 'Medium', 'Easy', NULL,
	'Rule 1: (http.request.uri.path eq "/merchant" and http.request.uri.query contains "action=lookup_price"), Characteristics: IP, Rate: 10 requests / 2 minutes, Action: Managed Challenge. Rule 2: same expression, Rate: 20 requests / 5 minutes, Action: Block.',
	'https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/#prevent-content-scraping-via-query-string',
	'A lenient challenge rule followed by a stricter block rule reduces false positives for persistent but legitimate users. The same pattern applies to operations identified in the request body.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Rate Limit Content Scraping per Operation');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Rate Limit GraphQL Operations',
	'GraphQL APIs use a single path and mostly POST requests, so rate limit by operation name in the body (and, with API Shield, by query complexity) instead of by path and method.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'API Security'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Rate Limiting Rules'),
	'Situational', 'Medium', 'Medium', 'Advanced Rate Limiting and payload inspection.',
	'Expression: (http.request.uri.path eq "/graphql" and http.request.body.raw contains "createReview"). Characteristics: Cookie (session_id). Rate: 5 requests / 1 hour. Action: Block.',
	'https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/#protecting-graphql-apis',
	'Also consider limiting the total query complexity per client over time and the complexity of individual queries (GraphQL malicious query protection in API Shield).'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Rate Limit GraphQL Operations');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Protect LLM Endpoints with AI Security for Apps',
	'Detect and mitigate prompt injection, PII in prompts, and unsafe topics on LLM-powered endpoints (chatbots, assistants) with AI Security for Apps (formerly Firewall for AI).',
	'Security', (SELECT category_id FROM Categories WHERE name = 'AI Security'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'AI Security for Apps'),
	'Situational', 'High', 'Medium', 'LLM endpoints labeled cf-llm in Web Assets; JSON request bodies.',
	'(cf.llm.prompt.injection_score lt 20) or (cf.llm.prompt.pii_detected)',
	'https://developers.cloudflare.com/waf/detections/ai-security-for-apps/',
	'Start with Log and review Security Analytics filtered by the cf-llm label. Combine signals to reduce false positives, for example (cf.llm.prompt.injection_score lt 25 and cf.bot_management.score lt 10). LLM endpoint discovery is available on all plans; detection fields require an Enterprise add-on.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Protect LLM Endpoints with AI Security for Apps');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Scan Uploads for Malicious Content',
	'Use WAF content scanning to detect malware in uploaded files and block requests that contain malicious content objects.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'WAF Custom Rules'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Malicious Uploads Detection'),
	'Situational', 'High', 'Easy', 'Malicious uploads detection enabled (Enterprise add-on).',
	'(cf.waf.content_scan.has_malicious_obj)',
	'https://developers.cloudflare.com/waf/detections/malicious-uploads/',
	'Also log requests where scanning failed or the body was truncated (cf.waf.content_scan.has_failed, cf.waf.content_scan.truncated) to spot gaps, and restrict allowed file types with cf.waf.content_scan.obj_types.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Scan Uploads for Malicious Content');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Use Threat Intelligence in WAF Rules',
	'Match client IPs against Cloudforce One threat intelligence (IPs involved in DDoS or WAF attack activity in the past seven days) and combine it with other signals.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'WAF Custom Rules'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Threat Intelligence'),
	'Situational', 'Medium', 'Easy', 'Active Cloudforce One subscription.',
	'(any(cf.intel.ip.datasets[*] == "waf") and cf.waf.score lt 20)',
	'https://developers.cloudflare.com/waf/detections/threat-intelligence/',
	'IP addresses are often shared (NAT, proxies, cloud providers): test with Log first and combine with Attack Score or bot signals before blocking. Since Birthday Week 2026, the Threat Events Platform and Threat Signals are free for every account for investigations.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Use Threat Intelligence in WAF Rules');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Control AI Crawlers by Purpose (Search, Agent, Training)',
	'Use AI Crawl Control to decide separately whether AI search crawlers, AI agents, and AI training crawlers may access your content, and monitor robots.txt compliance.',
	'General', (SELECT category_id FROM Categories WHERE name = 'Bot Management'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'AI Crawl Control'),
	'Recommended', 'Medium', 'Easy', NULL,
	'AI Crawl Control: set Search, Agent, and Training to allow, block on all pages, or block only on pages with ads. Optionally block individual crawlers and enforce robots.txt.',
	'https://developers.cloudflare.com/ai-crawl-control/',
	'Available on all plans, including Free. robots.txt and Content Signals only express preferences; use block actions to enforce them. Agents that sign requests with Web Bot Auth can be identified with cf.bot_management.signed_agent.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Control AI Crawlers by Purpose (Search, Agent, Training)');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Enable Post-Quantum Encryption to the Origin',
	'Make sure the origin server supports the hybrid post-quantum key agreement X25519MLKEM768 over TLS 1.3, so the Cloudflare-to-origin connection is protected against harvest-now, decrypt-later attacks.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'SSL/TLS'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'SSL/TLS'),
	'Recommended', 'Medium', 'Medium', 'TLS 1.3 on the origin server.',
	'bssl client -connect <YOUR_ORIGIN>:443 -curves X25519MLKEM768',
	'https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-to-origin/',
	'Automatic key exchange (on by default) prefers X25519MLKEM768 whenever the origin supports it; only about 15% of origins did as of Birthday Week 2026. Verify that the handshake reports X25519MLKEM768. Monitor visitor-side adoption in HTTP Traffic Analytics or with the ClientTLSKeyExchangeGroup Logpush field.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Enable Post-Quantum Encryption to the Origin');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Enforce a Positive Security Model with Application Profiles',
	'Let Cloudflare learn the expected structure of requests to your web application (data types, ranges, formats) and act on non-conforming requests with Security Rules.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'API Security'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'API Shield'),
	'Situational', 'High', 'Medium', 'Closed beta for invited Enterprise customers; customers with API Security already have access.',
	'Onboard the application in Web Assets, select operations to profile, review conforming and non-conforming traffic in observation mode, then create Security Rules for selected paths, operations, or fields.',
	'https://blog.cloudflare.com/application-profiles/',
	'An operation needs at least 1,000 requests with a 2xx response in the previous seven days to learn fields (10,000 to learn data boundaries). Profiles relearn weekly; pin a learned schema by uploading it to Schema Validation.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Enforce a Positive Security Model with Application Profiles');
