-- Content review, 2026-10-15. Prepared against a production export containing 102 practices.
-- Evidence and application instructions: data/content-review-2026-10-15.md.
-- Apply after migrations, first to an isolated production copy with --local --persist-to=<review-state>.
-- Updates preserve practice IDs. Omitted JSON keys preserve existing columns; JSON null clears a column.
-- The difference predicates also preserve updated_at on a second run. No schema/index changes.

-- Feature labels describe entry-level availability; individual capabilities still need prerequisites.
WITH reviewed(name, subscription_level) AS (VALUES
	('WAF', 'Free'),
	('Rate Limiting Rules', 'Free'),
	('Bot Management', 'Paid Add-On'),
	('Cloudflare Access', 'Free'),
	('mTLS', 'Free'),
	('Advanced Certificate Manager', 'Paid Add-On'),
	('Argo Smart Routing', 'Paid Add-On')
)
UPDATE CloudflareFeatures AS feature
SET subscription_level = reviewed.subscription_level
FROM reviewed
WHERE feature.name = reviewed.name AND feature.subscription_level IS NOT reviewed.subscription_level;

INSERT INTO CloudflareFeatures (name, feature_url, subscription_level)
SELECT 'Cloudflare Tunnel', 'https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/', 'Free'
WHERE NOT EXISTS (SELECT 1 FROM CloudflareFeatures WHERE name = 'Cloudflare Tunnel');

-- Only the explicitly reviewed fields change. Each practice retains its ratings unless a patch says otherwise.
WITH corrections(practice_id, patch) AS (VALUES
	(3, json_object(
		'title', 'Test Rules with Plan-Appropriate Observation',
		'description', 'Observe the expected matches before enforcing a WAF custom rule or rate limiting rule. Use Log where available, then deploy a narrowly scoped mitigation and monitor Security Events.',
		'prerequisites', 'Log for custom rules and rate limiting rules requires Enterprise. Other fields, periods, actions, and quotas depend on the plan and contract.',
		'notes', 'Dry run validates configuration, not traffic matches. Without Log, estimate matches with analytics, use conservative thresholds, and test one host/path first. Managed Challenge is appropriate only for interactive browser traffic; APIs need non-interactive controls. Security Events may be sampled.',
		'source_reference', 'https://developers.cloudflare.com/waf/custom-rules/create-dashboard/'
	)),
	(4, json_object(
		'prerequisites', 'Pro or above for the Cloudflare Managed Ruleset. Free zones receive the Free Managed Ruleset. Account-level deployments require eligible Enterprise zones.',
		'notes', 'Deploy the Cloudflare Managed Ruleset at the account or zone level with explicit hostname coverage. Before removing a zone deployment, verify that the account execute expression covers those hosts. Create exceptions for confirmed false positives, scoped to specific rule IDs and affected operations.'
	)),
	(5, json_object('prerequisites', 'Cloudflare Managed Ruleset deployed (Pro or above).', 'notes', 'Rule 882b37d6bd5f4bf2a3cdb374d503ded0 was disabled with default action Block in managed version 407 on 2026-10-15. Review current metadata and traffic before enabling an override; defaults can change.')),
	(6, json_object('prerequisites', 'Cloudflare Managed Ruleset deployed (Pro or above).', 'notes', 'Rule 6e759e70dc814d90a003f10424644cfb was disabled with default action Block in managed version 407 on 2026-10-15. Test application path handling before enabling it; review current metadata.')),
	(7, json_object(
		'title', 'Observe Large Request Bodies with the Managed Rule',
		'prerequisites', 'Cloudflare Managed Ruleset deployed (Pro or above).',
		'expressions_configuration_details', 'Review Rule ID 7b822fd1f5814e17888ded658480ea8f (Anomaly:Body - Large 2). Enable only with an explicitly chosen action after testing upload endpoints.',
		'notes', 'In managed version 407 on 2026-10-15 this rule was disabled with default action Log, not Block. Enabling it alone does not guarantee mitigation. A large body is not proof of malware; use malicious uploads detection for binary uploads and define an endpoint-specific size policy.'
	)),
	(8, json_object('prerequisites', 'Cloudflare Managed Ruleset deployed (Pro or above).', 'notes', 'Rule 8e361ee4328f4a3caf6caf3e664ed6fe was disabled with default action Block in managed version 407 on 2026-10-15. Alternatively use a scoped custom rule with not cf.edge.server_port in {80 443}. Retain application ports that are intentionally exposed.')),
	(9, json_object('prerequisites', 'Cloudflare Managed Ruleset deployed (Pro or above).', 'notes', 'Rules ab53f93c9b03472ab34a5405d9bdc7d5 and 6e2240ffcb87477bbd4881b6fd13142f were disabled with default action Block in managed version 407 on 2026-10-15. Standard API and CORS methods are not inherently malicious; check endpoint contracts before overriding.')),
	(10, json_object(
		'description', 'Review vulnerability-scanner rules against expected security testing and your application stack. Enable selected disabled rules rather than overriding every scanner rule indiscriminately.',
		'prerequisites', 'Cloudflare Managed Ruleset deployed (Pro or above).',
		'notes', 'Current managed definitions must be inspected: in version 407, rule 0242110ae62e44028a13bf4834780914 was already enabled while 223829d453cc4a0e9324811f3a9dc737 was disabled. Default definitions are not proof of effective zone/account enforcement; inspect execute rules and overrides.'
	)),
	(11, json_object(
		'prerequisites', 'Enterprise WAF with payload logging entitlement; Super Administrator to configure it; a customer-managed encryption key pair.',
		'notes', 'Upload the public key and retain the private key securely outside Cloudflare. Logging captures matched payloads only after enablement; Cloudflare cannot decrypt them and will not request the private key. Preserve payload logging configuration when patching execute rules.',
		'source_reference', 'https://developers.cloudflare.com/waf/managed-rules/payload-logging/'
	)),
	(12, json_object(
		'title', 'Scope Browser Integrity Check Exceptions to Non-Browser Traffic',
		'description', 'If Browser Integrity Check causes confirmed false positives for APIs or legitimate automation, disable it only for those requests rather than disabling the protection zone-wide.',
		'recommendation_level', 'Situational',
		'expressions_configuration_details', 'Use a Configuration Rule scoped to the affected hostname/path, or a narrowly scoped custom Skip rule selecting the Browser Integrity Check product.',
		'notes', 'BIC is outside the normal WAF phases: skipping a Ruleset Engine phase does not skip BIC. Retain checks for other traffic and keep origin authentication in place.'
	)),
	(13, json_object(
		'prerequisites', 'Pro or above; Enterprise for Log action.',
		'notes', 'Cloudflare documents false positives and only marginal benefit on top of the Cloudflare Managed Ruleset plus WAF attack score. Start with low paranoia and a high anomaly threshold, preferably Log where available. Tune against traffic; there is no universal safe threshold. Use Managed Challenge only for browser navigations and narrow specific-rule exceptions for confirmed false positives.'
	)),
	(14, json_object(
		'title', 'Exempt Selected Verified Bots from Specific Mitigations',
		'description', 'Use verified bot categories to exempt only the crawlers or monitoring services that the application needs from bot-specific mitigations.',
		'expressions_configuration_details', '(http.host eq "www.example.com" and http.request.method in {"GET" "HEAD"} and cf.verified_bot_category in {"Search Engine Crawler" "Monitoring & Analytics"})',
		'notes', 'Example categories and hostname must be adapted. Skip is an exemption from selected rules/products, not a general Allow. Never skip authentication, mTLS, or API validation just because a request is a verified bot. Skip only the offending rule IDs or required phases and place the exception before those rules. Broad verified-bot exemptions can also exempt AI crawlers.'
	)),
	(15, json_object(
		'title', 'Use Authenticated, Narrow API Exceptions',
		'description', 'For a confirmed API false positive, exempt a precise operation and a verified identity from only the responsible mitigation. A client-supplied header or a high attack score is not authentication.',
		'recommendation_level', 'Situational',
		'prerequisites', 'mTLS enabled on the example hostname and valid client certificates issued to the intended integration; alternatively use verified JWT claims with the appropriate entitlement.',
		'expressions_configuration_details', '(http.host eq "api.example.com" and http.request.uri.path eq "/api/resources" and http.request.method eq "GET" and cf.tls_client_auth.cert_verified and not cf.tls_client_auth.cert_revoked)',
		'notes', 'Restrict the example to the intended certificate identity/CA when multiple clients share the hostname. Do not trust x-api-shield, Authorization presence, a bot score, or WAF score as identity. Select individual managed rule IDs for a managed-rule exception; do not skip schema/JWT checks or all remaining authentication rules.'
	)),
	(16, json_object(
		'title', 'Customize Responses for Blocked Requests',
		'description', 'Return a short branded or machine-readable error for blocked requests. A WAF Block response is an error response, not an HTTP redirect.',
		'prerequisites', 'Pro or above for custom Block responses.',
		'expressions_configuration_details', 'For an existing custom rule with action Block, choose response type application/json, status 403, and body {"error":"Forbidden"}. Use Redirect Rules for an actual supported HTTP redirect.',
		'notes', 'Custom-rule Block responses support status codes 400-499 and at most 2 KB. An HTML meta refresh relies on browser behavior and is unsuitable for APIs. Do not send blocked clients to a plaintext HTTP URL.',
		'source_reference', 'https://developers.cloudflare.com/waf/custom-rules/create-dashboard/#configure-a-custom-response-for-blocked-requests'
	)),
	(18, json_object(
		'title', 'Observe Methods Unexpected for a Specific Endpoint',
		'description', 'Compare request methods to the contract of a particular endpoint rather than treating standard methods such as POST, HEAD, OPTIONS, PATCH, or DELETE as inherently suspicious.',
		'prerequisites', 'Enterprise for a custom rule with Log action.',
		'expressions_configuration_details', '(http.host eq "www.example.com" and http.request.uri.path eq "/public/about" and not http.request.method in {"GET" "HEAD"})',
		'notes', 'Use Log initially. The example represents a read-only page; change the method set for your endpoint and preserve required CORS OPTIONS requests. Where Log is unavailable, inspect analytics before deploying a narrow policy.'
	)),
	(19, json_object(
		'prerequisites', 'Attack score detection enabled. The numeric cf.waf.score field is documented for Enterprise; cf.waf.score.class requires Business or above. Validate actual entitlement.',
		'notes', 'Lower scores are more suspicious; 100 means unscored, not clean. The September 2026 announcement describes wider availability, but the field references still specify Enterprise for numeric scores and Business for classes as of 2026-10-15. Confirm with validation rather than assuming rollout completion. Observe a scoped threshold first (Log requires Enterprise), then Block for APIs or Managed Challenge for browser navigations. Handle reported detection failures explicitly.',
		'source_reference', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.waf.score/'
	)),
	(20, json_object(
		'prerequisites', 'Enterprise for Cloudflare Managed IP Lists.',
		'expressions_configuration_details', '(ip.src in $cf.botnetcc or ip.src in $cf.malware)',
		'notes', 'The documented list names are $cf.botnetcc, $cf.malware, $cf.open_proxies, $cf.anonymizer, and $cf.vpn. Shared infrastructure, VPNs, and anonymizers can be legitimate: use endpoint scope and observed traffic before enforcing broad restrictions.'
	)),
	(22, json_object(
		'expressions_configuration_details', '(http.host eq "www.example.com" and ip.src.asnum in {64500})',
		'notes', 'The ASN is an illustrative placeholder, not a deny recommendation. Build a list from observed abuse and business policy; large cloud/CDN ASNs also host customers, webhooks, and monitoring. Enterprise supports custom ASN lists; other plans can use supported inline values or IP lists. Geo/ASN signals are not authentication.'
	)),
	(23, json_object(
		'title', 'Apply Approved Geographic Access Policies',
		'description', 'Apply an explicitly approved regional policy to the relevant application using IP geolocation. Do not present a static country list as an OFAC sanctions implementation.',
		'prerequisites', 'A current business/legal policy defining allowed locations and exceptions.',
		'expressions_configuration_details', '(http.host eq "regional.example.com" and not ip.src.country in {"US" "GB"})',
		'notes', 'US and GB are illustrative allowed locations, not a sanctions recommendation. Sanctions can target persons, entities, sectors, and regions; a country allow/deny rule is not sufficient sanctions screening. Geolocation can be inaccurate and VPNs change apparent location. Prefer identity-based controls for private applications.',
		'source_reference', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.country/'
	)),
	(24, json_object('notes', 'User-Agent is client-controlled and easily spoofed. curl, Python, Go, and empty headers can be legitimate integrations. Scope to browser-only hosts/paths and inventory legitimate automation before blocking; this signal is not a strong bot identity.')),
	(25, json_object(
		'prerequisites', 'An account IP list named allowed_ips containing trusted source addresses, or a separately configured Access application.',
		'expressions_configuration_details', '(http.host eq "www.example.com" and (http.request.uri.path eq "/wp-admin" or starts_with(http.request.uri.path, "/wp-admin/") or http.request.uri.path eq "/wp-login.php") and http.request.uri.path ne "/wp-admin/admin-ajax.php" and not ip.src in $allowed_ips)',
		'notes', 'Action: Block. The path boundary avoids matching unrelated prefixes. Preserve public AJAX and any other plugin/form callbacks that your site needs after testing. Prefer Cloudflare Access for identity-based administration; an IP allowlist is not a substitute for WordPress authentication.'
	)),
	(26, json_object(
		'title', 'Protect Employee Portals with Identity-Based Access',
		'description', 'Protect internal applications with Cloudflare Access and verified identity policies. Geography is an optional additional restriction, not proof that the requester is an employee.',
		'expressions_configuration_details', 'Configure an Access application for portal.example.com with explicit identity policies. Optional regional restriction: (http.host eq "portal.example.com" and not ip.src.country in {"US" "GB"}).',
		'notes', 'Example countries must follow your policy and travel requirements. Protect the origin from direct bypass and validate Access JWTs. Access has separate Zero Trust plans; an Enterprise website plan is not a prerequisite for basic Access.'
	)),
	(27, json_object('prerequisites', 'Client certificates installed and mTLS enabled for each protected hostname. Cloudflare-issued client certificates are available on all plans within quota; BYOCA requires Enterprise.', 'notes', 'Configure a blocking policy for missing, invalid, or revoked certificates after enabling mTLS. Zone-level client certificates, Access mTLS Service Auth, and Authenticated Origin Pulls are separate products with different purposes and entitlements.')),
	(28, json_object('prerequisites', 'Zone-level mTLS configured, client certificate inventory, and a revocation process.', 'notes', 'Reject revoked certificates in addition to requiring successful verification. Test revocation with a real client and maintain safe certificate rotation. Access mTLS has separate Zero Trust plan requirements; do not conflate it with zone-level client certificates.')),
	(29, json_object(
		'prerequisites', 'mTLS configured on the intended hostname and an approved client-certificate inventory.',
		'expressions_configuration_details', '(http.host eq "mtls.example.com" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked or not cf.tls_client_auth.cert_serial in {"SPECIFIC_SERIAL_NUMBER"}))',
		'notes', 'Action: Block. Replace the serial placeholder with an actual approved value. A serial allowlist must also require successful validation and reject revoked certificates; serial numbers alone are not identity and are not globally unique across issuers. Pin the expected issuer or fingerprint where appropriate and plan rotation.'
	)),
	(30, json_object(
		'title', 'Mitigate Admin JWT Requests with Low WAF Attack Scores',
		'description', 'For authenticated admin operations, combine verified JWT claims with a low WAF attack score to identify suspicious requests. Lower scores indicate higher attack risk.',
		'prerequisites', 'API Shield JWT validation configuration and Enterprise numeric WAF attack score detection enabled.',
		'expressions_configuration_details', '(http.host eq "api.example.com" and starts_with(http.request.uri.path, "/admin/") and any(cf.api_gateway.tokens.valid[*] eq "<TOKEN_CONFIGURATION_ID>") and lookup_json_string(http.request.jwt.claims["<TOKEN_CONFIGURATION_ID>"][0], "user") eq "admin" and cf.waf.score lt 40)',
		'notes', 'Threshold 40 is illustrative; observe matches before enforcement. Use Block for non-interactive API requests. Independently require a valid token, the expected issuer/audience/claims, and application authorization: this rule does not reject unauthenticated requests by itself.'
	)),
	(32, json_object(
		'description', 'Enforce JavaScript Detections on selected browser navigation endpoints after the visitor has already received an HTML page with the detection script.',
		'expressions_configuration_details', '(http.host eq "www.example.com" and http.request.uri.path eq "/account/overview" and http.request.method eq "GET" and not cf.bot_management.js_detection.passed and not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',
		'notes', 'Action: Managed Challenge, not unconditional Block. JSD must be enabled and CSP must permit it. Choose a post-entrypoint HTML navigation; do not use on first visits, APIs, native apps, or WebSockets. A failed or absent result can be legitimate.'
	)),
	(33, json_object('notes', 'IPv6 is not inherently malicious. Broadly blocking it can exclude legitimate clients; prefer prefix-aware abuse controls when available. Check the documented availability before proposing to disable IPv6 compatibility: it cannot be disabled on every plan.')),
	(36, json_object(
		'prerequisites', 'Leaked credentials detection enabled with correctly configured authentication detection locations. password_leaked is available on all plans; username_and_password_leaked requires Pro or above.',
		'expressions_configuration_details', '(http.host eq "www.example.com" and http.request.uri.path eq "/api/login" and http.request.method eq "POST" and cf.waf.credential_check.username_and_password_leaked)',
		'notes', 'The example uses the more precise leaked username/password pair (Pro or above); Free can use password_leaked with greater false-positive risk. Prefer a recovery/password-reset workflow over blindly rejecting legitimate users. Use non-interactive controls for API login requests and decide how detection failures are handled.'
	)),
	(37, json_object(
		'expressions_configuration_details', '(http.host eq "www.example.com" and http.request.method eq "POST" and http.request.timestamp.sec ge 1792022400 and http.request.timestamp.sec lt 1792026000)',
		'notes', 'Example only: 2026-10-15 00:00-01:00 UTC. Replace the window before deploying and use explicit start/end boundaries. The field is integer UNIX epoch seconds, not a fixed-width 10-digit string; remove or disable expired maintenance rules.'
	)),
	(38, json_object(
		'expressions_configuration_details', '(http.host eq "www.example.com" and not cf.worker.upstream_zone in {"" "example.com"})',
		'notes', 'Use the Rules field, not the client-supplied CF-Worker header. Inventory legitimate partner and SaaS/O2O Worker traffic before enforcement. The upstream zone identifies a calling zone, not an authorized user; retain application authentication.',
		'source_reference', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.worker.upstream_zone/'
	)),
	(39, json_object(
		'prerequisites', 'Business or eligible Enterprise for this hostname+method expression; Free/Pro must simplify to fields their rate limiting plan supports.',
		'expressions_configuration_details', 'Match: (http.host eq "www.example.com" and http.request.uri.path eq "/login" and http.request.method eq "POST"). API characteristics: ["ip.src", "cf.colo.id"]. Set threshold, counting period, and mitigation timeout from observed traffic. Action: Block; Log is Enterprise-only.',
		'notes', 'Counters are per data center, not a precise global quota. Consider IP with NAT support where available to avoid aggregating unrelated users. Authenticated identities require appropriate advanced characteristics. Do not use interstitial challenges for non-interactive API clients.'
	)),
	(40, json_object(
		'prerequisites', 'Business or eligible Enterprise for method-based matching; Advanced Rate Limiting for session-based characteristics.',
		'expressions_configuration_details', 'Match: (http.host eq "www.example.com" and http.request.uri.path eq "/upload" and http.request.method in {"POST" "PUT" "PATCH"}). API characteristics: ["ip.src", "cf.colo.id"]. Action: Block, with measured threshold, counting period, and mitigation timeout.',
		'notes', 'Throttle is action behavior, not an action name. Where the Enterprise contract permits it, configure Block with mitigation_timeout: 0 to throttle excess requests. Rate limits do not impose file-size limits or scan uploads for malware.'
	)),
	(41, json_object(
		'prerequisites', 'Enterprise with Advanced Rate Limiting for cookie/header/custom characteristics.',
		'expressions_configuration_details', 'Match: (http.host eq "www.example.com" and http.request.uri.path eq "/login" and http.request.method eq "POST"). API characteristics for an IP limit: ["ip.src", "cf.colo.id"]. Create a separate identity-based rule when a validated session/user identifier is available. Action: Block.',
		'notes', 'Combining IP and a rotatable cookie in one key creates a counter per combination and may make evasion easier; it is not two independent limits. Repeat the intended scope in a custom counting expression. Response-based counting requires Business or eligible Enterprise and can bypass cache. Throttling is Enterprise Block behavior, not a separate action.'
	)),
	(42, json_object(
		'prerequisites', 'Eligible Enterprise rate limiting with leaked-credentials fields; enable leaked credentials detection. Advanced Rate Limiting is needed for session/custom characteristics.',
		'expressions_configuration_details', 'Match: (http.host eq "www.example.com" and http.request.uri.path eq "/login" and http.request.method eq "POST" and cf.waf.credential_check.username_and_password_leaked). API characteristics: ["ip.src", "cf.colo.id"]. Use an observed threshold and Block action.',
		'notes', 'Leaked username/password pairs reduce false positives compared with password-only detection. Scope to the actual authentication endpoint and provide account-recovery paths. A detection returning no result is not proof that credentials are safe.'
	)),
	(43, json_object('prerequisites', 'A rate limiting plan/contract supporting country-based expressions; verify availability before deploying.', 'notes', 'Use observed traffic and an approved regional policy, not a list of supposedly malicious countries. Scope to the intended hostname/operation and include cf.colo.id in API characteristics; counters are per data center.')),
	(44, json_object(
		'prerequisites', 'Enterprise with Advanced Rate Limiting and Custom characteristics.',
		'expressions_configuration_details', 'Match: (http.host eq "www.example.com" and http.request.uri.path eq "/login" and http.request.method eq "POST"). API characteristics: ["cidr6(ip.src, 64)", "cf.colo.id"]. Set rate/period/action from measured traffic.',
		'notes', 'cidr6 passes IPv4 through unchanged. /64 is a starting point for subscriber-prefix aggregation, not a universal identity; /48 combines many more clients. Confirm assignment patterns and false positives before changing prefix length. Without Advanced Rate Limiting, use supported IP or IP with NAT support characteristics.'
	)),
	(45, json_object(
		'prerequisites', 'mTLS enabled on the hostname, Cloudflare certificate forwarding configured, and Enterprise Advanced Rate Limiting for header characteristics.',
		'expressions_configuration_details', 'Match: (http.host eq "mtls.example.com" and cf.tls_client_auth.cert_verified and not cf.tls_client_auth.cert_revoked). With certificate forwarding enabled, use the authoritative cf-client-cert-sha256 header value as the characteristic and include cf.colo.id in the API configuration.',
		'notes', 'Configure and verify Cloudflare certificate forwarding first; do not trust an arbitrary client-provided fingerprint header. Header names in API expressions are lowercase. Rate limiting does not replace rejecting invalid/revoked certificates. Validate header availability and empty-value behavior on real mTLS requests.',
		'source_reference', 'https://developers.cloudflare.com/learning-paths/mtls/mtls-app-security/related-features/#rate-limiting-by-client-certificates'
	)),
	(46, json_object(
		'description', 'Rate limit repeated missing/failed JSD results only on browser navigation endpoints that are visited after an HTML bootstrap page.',
		'prerequisites', 'Enterprise Bot Management with JSD enabled and an Enterprise rate limiting entitlement; response counting fields must be available.',
		'expressions_configuration_details', 'Match: (http.host eq "www.example.com" and http.request.uri.path eq "/account/overview" and http.request.method eq "GET" and not cf.bot_management.js_detection.passed and not cf.bot_management.verified_bot). API characteristics: ["ip.src", "cf.colo.id"]. If counting HTML responses, repeat the full match expression and add any(http.response.headers["content-type"][*] contains "text/html").',
		'notes', 'A counting expression replaces the default match expression for counting; an HTML-only counter without the original scope can count unrelated traffic. Response fields can bypass cache. Do not apply this to first visits, APIs, WebSockets, or native apps. Use browser-appropriate mitigation and retain a safe bootstrap path.'
	)),
	(47, json_object(
		'notes', 'Your backend must call Siteverify and reject invalid tokens before performing the protected action. Keep the secret server-side and validate expected hostname/action when used. Tokens expire after 300 seconds and are single-use; refresh expired/redeemed tokens. Optional pre-clearance does not replace Siteverify or application authentication.',
		'source_reference', 'https://developers.cloudflare.com/turnstile/get-started/server-side-validation/'
	)),
	(49, json_object(
		'description', 'Use Advanced Certificate Manager when you need its additional hostname coverage or certificate customization; Universal SSL remains appropriate when it meets your requirements.',
		'recommendation_level', 'Situational',
		'prerequisites', 'Advanced Certificate Manager paid add-on; validate required certificate and TLS capabilities separately.',
		'notes', 'ACM is not required just to enable TLS 1.3, Always Use HTTPS, or a minimum TLS version. Confirm full hostname coverage and successful certificate deployment before replacing an existing edge certificate.'
	)),
	(50, json_object(
		'title', 'Disable Universal SSL Only with Verified Replacement Coverage',
		'description', 'Keep Universal SSL unless there is a specific reason to remove it. If disabling it, verify active replacement edge certificates cover every required hostname first.',
		'prerequisites', 'Active ACM or custom edge certificates with complete hostname coverage and a documented renewal/recovery process.',
		'notes', 'An origin certificate is not an edge certificate. Disabling Universal SSL can break HTTPS on uncovered hostnames. Confirm certificate status, expiry, apex/wildcard coverage, and recovery before making the zone change.'
	)),
	(65, json_object(
		'description', 'Use Authenticated Origin Pulls to require Cloudflare to present a client certificate when connecting to the origin. Use a custom certificate when you need to authenticate your specific configuration.',
		'prerequisites', 'Origin-side client certificate verification and Full or Full (strict) mode. Custom/per-hostname certificate options depend on entitlement.',
		'notes', 'The shared Cloudflare AOP certificate proves only that traffic comes from the Cloudflare network, not your account or zone. For stronger isolation, upload a customer-specific certificate and trust only its CA at the origin. Also restrict direct origin access and prefer Full (strict) for server certificate verification.',
		'source_reference', 'https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/'
	)),
	(66, json_object('notes', 'Rotating an exposed IP is only one layer. Restrict inbound origin traffic to the required trusted sources or use Tunnel; otherwise the new IP can be discovered and used to bypass the WAF. Remove accidental DNS-only exposure and authenticate Cloudflare-to-origin traffic.')),
	(71, json_object(
		'recommendation_level', 'Situational',
		'prerequisites', 'Enterprise Bot Management; JSD enabled; CSP permits the detection script; an earlier HTML page already bootstraps browser clients.',
		'expressions_configuration_details', '(http.host eq "www.example.com" and http.request.uri.path eq "/account/overview" and http.request.method eq "GET" and starts_with(http.user_agent, "Mozilla/5.0") and not cf.bot_management.js_detection.passed and not cf.bot_management.verified_bot and not cf.bot_management.static_resource)',
		'notes', 'Use Managed Challenge on a post-bootstrap browser navigation. The User-Agent is only a weak hint and can be spoofed; it does not prove that JavaScript ran. Exclude first visits and non-browser clients rather than enforcing JSD across all Mozilla requests.'
	)),
	(72, json_object(
		'title', 'Rate Limit Browser Sessions with Cookie Characteristics',
		'description', 'Use cookie-based counters for selected browser workflows, with separate limits for clients that have no valid session and protections against token rotation.',
		'expressions_configuration_details', 'For an authenticated session cookie, scope the match to the intended browser endpoint and use the selected cookie value plus cf.colo.id as API characteristics. Treat cf_clearance-based limiting as an optional secondary control.',
		'notes', 'cf_clearance records a challenge clearance, not a logged-in user identity. Missing cookies share a missing-value counter and empty values are distinct. Attackers can obtain/rotate cookies, so retain independent IP and authenticated-user limits where needed. Challenge Passage does not universally exempt rate limiting actions.',
		'source_reference', 'https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/'
	)),
	(74, json_object(
		'recommendation_level', 'Situational',
		'notes', 'Decide whether the application redirects HTTP to HTTPS or rejects it. Always Use HTTPS can answer before the WAF, so enabling both does not guarantee that a not ssl rule blocks plaintext requests. Verify phase order and live behavior. Redirection cannot protect the initial plaintext request; use HSTS for capable clients and require HTTPS in API clients.',
		'source_reference', 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/'
	)),
	(76, json_object(
		'description', 'Keep Cloudflare HTTP DDoS protection and relevant botnet-category rules enabled with their default settings unless a confirmed false positive requires a narrow override.',
		'notes', 'Historic quarterly percentages describe a reporting period, not a durable property of your traffic. Review current rule categories and DDoS analytics; do not lower protection solely because of a past report.'
	)),
	(77, json_object(
		'description', 'Use current attack analytics to identify suspicious client patterns, and combine User-Agent with affected hostname/path and additional signals before creating a mitigation.',
		'expressions_configuration_details', '(http.host eq "www.example.com" and http.request.uri.path eq "/expensive-search" and lower(http.user_agent) contains "fasthttp")',
		'notes', 'The example is a weak, spoofable signal, not a universal deny policy. Old browser User-Agent lists become stale and match legitimate browsers; use current observed evidence and plan-supported rate limits. Rules-language inline sets use whitespace separators, not commas.'
	)),
	(78, json_object(
		'description', 'Restrict methods that an endpoint does not support, using its actual application contract rather than historical DDoS method percentages.',
		'expressions_configuration_details', '(http.host eq "www.example.com" and http.request.uri.path eq "/public/about" and not http.request.method in {"GET" "HEAD"})',
		'notes', 'DELETE, PATCH, HEAD, and OPTIONS are standard legitimate methods where the application expects them. Account for CORS and API schemas; use a narrow Block policy only for unsupported methods.'
	)),
	(79, json_object(
		'description', 'Protect application-specific expensive or sensitive paths using current traffic evidence, rather than assuming paths from an old DDoS report are abusive everywhere.',
		'expressions_configuration_details', '(http.host eq "www.example.com" and (http.request.uri.path eq "/wp-login.php" or starts_with(http.request.uri.path, "/wp-login.php/")))',
		'notes', 'Match only if WordPress is relevant to your site. ends_with is a function and does not interpret [0-9]+ as a regex; use matches only with supported Business/Enterprise regex entitlement when a true pattern is needed. Use measured rate limits for real login endpoints and Block probes for software you do not run.'
	)),
	(80, json_object(
		'title', 'Apply Network-Layer Policies with the Appropriate Product',
		'description', 'For networks protected by Magic Transit, use Cloudflare Network Firewall policies and current network analytics to restrict unwanted traffic.',
		'prerequisites', 'Magic Transit and the relevant network firewall entitlement; a policy based on your protected prefixes and expected traffic.',
		'expressions_configuration_details', 'Configure a network firewall policy for the required protocol, destination prefix/port, and observed source policy. An HTTP WAF custom rule does not filter L3/L4 packets.',
		'notes', 'The location of a Cloudflare ingress data center is not the source country of an attacker. Do not copy a historical list of locations into an HTTP country block. Network-layer products and application WAF rules have different scopes.',
		'source_reference', 'https://developers.cloudflare.com/cloudflare-one/traffic-controls/packet-filtering/'
	)),
	(81, json_object('notes', 'Magic Transit requires a separate service/contract and protected-prefix onboarding. HTTP WAF and rate limiting rules do not apply to arbitrary TCP/UDP applications; Spectrum or network-layer products provide the relevant coverage.')),
	(83, json_object(
		'notes', 'Tunnel creates outbound origin connections and can eliminate public inbound exposure when the origin firewall is configured accordingly. A published hostname is still public unless you add Access or application authentication. Validate Access JWTs at the origin and retain least-privilege ingress configuration.'
	)),
	(84, json_object('prerequisites', 'An Argo/Smart Shield paid service or eligible Enterprise contract/preview; confirm pricing before activation.', 'notes', 'Argo Smart Routing is now offered as part of Smart Shield. Measure origin-bound latency before and after enabling it; cached responses do not need the same origin routing optimization.')),
	(85, json_object('notes', 'Tiered Cache reduces origin fetches for eligible CDN-cached content. Workers fetch can participate in that caching path; the Workers Cache API is data-center-local and does not support Tiered Cache. Distinguish CDN fetch caching, Workers Cache, and the Workers Cache API when choosing an architecture.')),
	(86, json_object(
		'expressions_configuration_details', '(cf.worker.upstream_zone ne "" and cf.worker.upstream_zone ne "example.com")',
		'notes', 'Use a Request Header Transform Rule to overwrite a diagnostic header from this field, rather than trusting a client-supplied value. The calling zone is useful for provenance, not user authorization. This practice configures Transform Rules, not a Worker.'
	)),
	(87, json_object(
		'description', 'Do not send interstitial Challenge Pages to API, AJAX/XHR, native mobile, or WebSocket clients. Use API authentication, scoped Block/Log policies, and rate limiting; browser frontends may use Turnstile pre-clearance.',
		'notes', 'cf-mitigated: challenge identifies a Challenge Page response; detection alone does not let an API client solve it. Browser pre-clearance requires correct hostname/cookie configuration and does not replace mandatory Siteverify validation of Turnstile tokens or application authorization.'
	)),
	(88, json_object(
		'description', 'Protect native mobile APIs with validated authentication and, when appropriate, a separately provisioned mobile app/device attestation SDK. Vendor attestation tokens can be validated at the edge or origin.',
		'prerequisites', 'A documented mobile SDK/vendor integration and its own entitlement; API Shield plus Advanced Rate Limiting for edge JWT-claim rate limits, or equivalent origin validation.',
		'source_reference', 'https://approov.io/resource/quickstarts/',
		'notes', 'Approov publishes native-app SDK quickstarts and a Cloudflare Worker token-validation integration. This is not evidence of a universally available Cloudflare-branded Mobile SDK or bundled Enterprise entitlement. Verify the offered integration and contract. Enforce signature, expiry, expected claims, and application authorization; header presence alone must never bypass security. Do not enforce browser JSD on native apps.'
	)),
	(89, json_object(
		'prerequisites', 'Response Header Transform Rules or Custom Errors; cf.response.error_type is a response-phase field, not a WAF request field.',
		'expressions_configuration_details', 'not (starts_with(http.request.uri.path, "/cdn-cgi/challenge-platform/") or cf.response.error_type in {"managed_challenge" "iuam" "legacy_challenge" "country_challenge"})',
		'notes', 'Apply this condition only in supported response phases when modifying headers that could break challenges. Do not block/challenge the challenge-platform endpoint. Avoid blanket exemptions for all /cdn-cgi/ traffic: image and Zaraz paths may represent application requests.',
		'source_reference', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.response.error_type/'
	)),
	(90, json_object(
		'expressions_configuration_details', '(http.host eq "www.example.com" and (lower(http.request.uri.path) contains "/.git" or lower(http.request.uri.path) contains "/.svn" or lower(http.request.uri.path) contains "/.env" or lower(http.request.uri.path) contains "/.htaccess" or lower(http.request.uri.path) contains "/.htpasswd" or lower(http.request.uri.path) contains "/.ds_store" or ends_with(lower(http.request.uri.path), ".sql") or ends_with(lower(http.request.uri.path), ".bak") or ends_with(lower(http.request.uri.path), ".old") or lower(http.request.uri.path) in {"/wp-config.php" "/phpinfo.php"}) and not starts_with(http.request.uri.path, "/.well-known/"))',
		'notes', 'Action: Block; a 404 response is appropriate for probes where custom responses are available (Pro or above). Scope the example to your stack and preserve required /.well-known/ resources. Verify normalization/rewrite behavior; the durable fix is keeping secrets and backups outside the public origin.'
	)),
	(91, json_object(
		'expressions_configuration_details', 'curl --fail-with-body "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/$RULESET_ID/rules/$RULE_ID?dry_run=true" --request PATCH --header "Authorization: Bearer $CLOUDFLARE_API_TOKEN" --header "Content-Type: application/json" --data ''{"description":"Validate a scoped update","expression":"(http.host eq \"www.example.com\" and http.request.uri.path eq \"/.env\")","action":"block","enabled":true}''',
		'notes', 'Set IDs from the current configuration. Supported account/zone Rulesets mutation endpoints accept dry_run=true for POST/PUT/PATCH/DELETE and require the same authorization as the real write. Validation covers syntax, fields/functions, actions, phases, entitlements, quotas, and references. Normal 200 operations return result:null; normal 204 operations remain 204. This does not simulate traffic matches. PATCH a single rule; PUT of an entrypoint/ruleset replaces its rule list. Removing dry_run applies a real change, so review the identical payload first.',
		'source_reference', 'https://developers.cloudflare.com/ruleset-engine/rulesets-api/dry-run/'
	)),
	(92, json_object(
		'description', 'Apply a new mitigation to an approximate percentage of requests using hash_in_range() with cf.random_seed, then expand coverage while monitoring real traffic.',
		'prerequisites', 'Validated rule configuration and an observation/rollback plan; Log is Enterprise-only.',
		'expressions_configuration_details', '(http.host eq "www.example.com" and http.request.uri.path eq "/.env" and hash_in_range(0, 100, cf.random_seed) lt 10)',
		'notes', 'Available for HTTP products on all plans since 2026-10-02. Bounds are integer literals: min inclusive, max exclusive. Raise the comparison threshold (10, 25, 50, 100), not the hash range. The hash algorithm may change without notice, so ip.src does not guarantee a permanently stable client cohort. SaaS custom metadata can control a per-hostname percentage: hash_in_range(0, 100, cf.random_seed) lt coalesce(lookup_json_integer(cf.hostname.metadata, "rollout_pct"), 0). Validate percentages in 0-100.',
		'source_reference', 'https://developers.cloudflare.com/changelog/post/2026-10-02-hash-in-range-ga/'
	)),
	(93, json_object(
		'prerequisites', 'Business or eligible Enterprise for response-code counting and the illustrated method-based match. Verify the requested counting period and mitigation timeout.',
		'expressions_configuration_details', 'Match: (http.host eq "www.example.com" and http.request.uri.path in {"/api/otp/validate" "/account/verify" "/password-reset"} and http.request.method eq "POST"). API characteristics: ["ip.src", "cf.colo.id"]. Counting expression: (http.host eq "www.example.com" and http.request.uri.path in {"/api/otp/validate" "/account/verify" "/password-reset"} and http.request.method eq "POST" and http.response.code in {401 403}). Example threshold: 5 failures / 60 seconds; Block for 600 seconds, only if supported.',
		'notes', 'A custom counting expression replaces the default match expression, so repeat its scope. Response fields can bypass cache. After a failure threshold triggers, mitigation can also affect later valid submissions sharing that counter; do not promise zero impact. Tune against origin semantics and account/IP abuse, including SMS cost and recovery flows. If an Origin Rule rewrites Host, verify response-based counting still matches.'
	)),
	(94, json_object(
		'description', 'Mitigate clients generating many errors on selected browser navigation endpoints, using observed error rates and application behavior.',
		'prerequisites', 'Business or eligible Enterprise for response-based counting. Bot Management is not required when using cf.client.bot.',
		'expressions_configuration_details', 'Match: (http.host eq "www.example.com" and starts_with(http.request.uri.path, "/catalog/") and http.request.method eq "GET" and not cf.client.bot). API characteristics: ["ip.src", "cf.colo.id"]. Counting expression: (http.host eq "www.example.com" and starts_with(http.request.uri.path, "/catalog/") and http.request.method eq "GET" and not cf.client.bot and http.response.code in {403 404}). Example: 20 errors / 60 seconds. Managed Challenge only for browser navigations; use a non-interactive action for APIs.',
		'notes', 'Repeat full scope when counting. Response fields can bypass cache. Broken links and SPAs can produce legitimate errors, so use a measured threshold. Narrow the operation rather than applying a host-wide error policy. Host rewrites in Origin Rules can prevent response-time counters from incrementing.'
	)),
	(95, json_object(
		'expressions_configuration_details', 'Match: (http.host eq "api.example.com" and starts_with(http.request.uri.path, "/v1/") and any(cf.api_gateway.tokens.valid[*] eq "<TOKEN_CONFIGURATION_ID>")). Custom characteristic: lookup_json_string(http.request.jwt.claims["<TOKEN_CONFIGURATION_ID>"][0], "sub"); also include cf.colo.id. Require the selected subject claim and configure a separate IP-based rule for missing/invalid tokens.',
		'prerequisites', 'Enterprise Advanced Rate Limiting; API Shield JWT validation for the verified-claim example. Alternatively, a securely validated and stable API-key/session identifier.',
		'notes', 'Raw header presence does not authenticate a client. Attacker-controlled or rotating keys/tokens can create fresh counters; a verified stable subject is preferable for per-user limits. Include the relevant issuer/tenant scope if subjects are not globally unique. Missing characteristics share a separate counter and empty values are distinct; define both behaviors. Application authorization remains required.',
		'source_reference', 'https://developers.cloudflare.com/api-shield/security/jwt-validation/#rate-limit-by-jwt-claim'
	)),
	(96, json_object(
		'prerequisites', 'Business or eligible Enterprise for the illustrated 120/300-second counting periods; Free/Pro must use shorter supported periods and permitted fields.',
		'expressions_configuration_details', 'Match: (http.host eq "www.example.com" and http.request.uri.path eq "/merchant" and http.request.uri.query contains "action=lookup_price"). API characteristics: ["ip.src", "cf.colo.id"]. Illustrative escalation: stricter Block rule (20 / 300 seconds) before browser Managed Challenge rule (10 / 120 seconds), if supported.',
		'notes', 'Use measured thresholds and supported periods. A terminating challenge before a stricter block can prevent that block from running/counting, so verify execution order instead of assuming escalation. Query substring matching is illustrative; use exact parsed values when your plan supports them. APIs require non-interactive controls.'
	)),
	(97, json_object(
		'prerequisites', 'Enterprise Advanced Rate Limiting and permitted request-body fields; GraphQL malicious query protection additionally requires API Shield.',
		'expressions_configuration_details', 'Match: (http.host eq "api.example.com" and http.request.uri.path eq "/graphql" and http.request.method eq "POST" and http.request.body.raw contains "createReview"). API characteristics: ["ip.src", "cf.colo.id"], or a verified stable user/session identifier when configured. Set a measured rate/period and Block action.',
		'notes', 'Raw substring matching is not a GraphQL parser and may match comments/variables or miss alternate queries and batching. GraphQL malicious query protection parses supported POST payloads on paths ending in /graphql, with a documented 20 KiB parsing limit; guard its fields with cf.api_gateway.graphql.parsed_successfully. Handle unparsed requests explicitly and distinguish individual query size/depth from complexity-based rate budgets.'
	)),
	(98, json_object(
		'prerequisites', 'Enterprise AI Security for Apps detection entitlement, WAF enabled, cf-llm labeled endpoints, JSON bodies, and detection enabled.',
		'expressions_configuration_details', '(http.host eq "api.example.com" and http.request.uri.path eq "/chat" and http.request.method eq "POST" and (cf.llm.prompt.injection_score lt 20 or cf.llm.prompt.pii_detected))',
		'notes', 'LLM endpoint discovery is available on all plans; detection fields and the AI Security Log Mode Ruleset are paid Enterprise capabilities. Observe detector quality before enforcing a policy; threshold 20 is illustrative and PII can be legitimate input. Do not use cf.llm.prompt.detected as a reason to block every prompt. Log Mode records full request bodies: review data handling before enabling it. Handle failed prompt detections explicitly.'
	)),
	(99, json_object(
		'expressions_configuration_details', '(http.host eq "www.example.com" and http.request.uri.path eq "/upload" and http.request.method in {"POST" "PUT" "PATCH"} and cf.waf.content_scan.has_malicious_obj)',
		'notes', 'Enable the detector first; its fields do not mitigate by themselves. Also observe has_failed, truncated, and cf.appsec.request.failed_detections containing waf_content_scan. Absence of a malicious result is not proof that a truncated/unscannable file is safe. Choose a separate rejection/quarantine policy for sensitive uploads and retain origin validation.'
	)),
	(100, json_object(
		'prerequisites', 'Active Cloudforce One subscription for cf.intel.ip fields; numeric WAF attack score entitlement and enabled detection for the example.',
		'notes', 'Threat-intelligence values reflect recent IP activity and can aggregate different events; IPs may be shared. Observe and combine with endpoint-specific signals before blocking. Free investigation tools do not imply free access to cf.intel.ip rule fields. Treat detection failures separately; a missing score is not a clean request.'
	)),
	(101, json_object('notes', 'AI Crawl Control is available on all plans; robots.txt and Content Signals express preferences rather than guaranteed enforcement. Avoid broad verified-bot Skip rules that undermine the intended policy. cf.bot_management.signed_agent is a Bot Management field identifying known Web Bot Auth agents, not a guarantee that every signed client is trusted or a feature entitlement granted by AI Crawl Control. Do not edit product-managed rules outside the owning workflow.')),
	(103, json_object(
		'expressions_configuration_details', '(http.host eq "api.example.com" and http.request.uri.path eq "/v1/orders" and http.request.method eq "POST" and cf.schema_validation.learned.violated)',
		'notes', 'Enable the selected operations, review Profile Analysis, then enforce narrowly with a custom rule; a learned profile is not automatic mitigation. Operations need 1,000 successful requests in seven days to learn fields and 10,000 to learn value boundaries. Profiles relearn weekly; review drift and pin an approved schema if needed. Multipart, GraphQL, and XML are unsupported; operations without a profile are not classified.',
		'source_reference', 'https://developers.cloudflare.com/waf/detections/application-profiles/'
	))
)
UPDATE BestPractices AS bp
SET title = CASE WHEN json_type(c.patch, '$.title') IS NULL THEN bp.title ELSE json_extract(c.patch, '$.title') END,
	description = CASE WHEN json_type(c.patch, '$.description') IS NULL THEN bp.description ELSE json_extract(c.patch, '$.description') END,
	prerequisites = CASE WHEN json_type(c.patch, '$.prerequisites') IS NULL THEN bp.prerequisites ELSE json_extract(c.patch, '$.prerequisites') END,
	expressions_configuration_details = CASE WHEN json_type(c.patch, '$.expressions_configuration_details') IS NULL THEN bp.expressions_configuration_details ELSE json_extract(c.patch, '$.expressions_configuration_details') END,
	source_reference = CASE WHEN json_type(c.patch, '$.source_reference') IS NULL THEN bp.source_reference ELSE json_extract(c.patch, '$.source_reference') END,
	notes = CASE WHEN json_type(c.patch, '$.notes') IS NULL THEN bp.notes ELSE json_extract(c.patch, '$.notes') END,
	recommendation_level = CASE WHEN json_type(c.patch, '$.recommendation_level') IS NULL THEN bp.recommendation_level ELSE json_extract(c.patch, '$.recommendation_level') END,
	updated_at = CURRENT_TIMESTAMP
FROM corrections AS c
WHERE bp.practice_id = c.practice_id
	AND EXISTS (
		SELECT 1 FROM json_each(c.patch) AS item
		WHERE item.value IS NOT CASE item.key
			WHEN 'title' THEN bp.title
			WHEN 'description' THEN bp.description
			WHEN 'prerequisites' THEN bp.prerequisites
			WHEN 'expressions_configuration_details' THEN bp.expressions_configuration_details
			WHEN 'source_reference' THEN bp.source_reference
			WHEN 'notes' THEN bp.notes
			WHEN 'recommendation_level' THEN bp.recommendation_level
		END
	);

-- Correct product attribution while preserving existing IDs/permalinks.
UPDATE BestPractices SET feature_id = (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Magic Transit'), updated_at = CURRENT_TIMESTAMP
WHERE practice_id IN (80, 81) AND feature_id IS NOT (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Magic Transit');
UPDATE BestPractices SET feature_id = (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Cloudflare Tunnel'), updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 83 AND feature_id IS NOT (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Cloudflare Tunnel');
UPDATE BestPractices SET feature_id = (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Rules'), updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 86 AND feature_id IS NOT (SELECT feature_id FROM CloudflareFeatures WHERE name = 'Rules');

-- Fill four coverage gaps. Title guards prevent duplicate inserts on re-run.
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Handle Reported Security Detection Failures',
	'Observe security detections that report a failure and decide explicitly whether sensitive operations reject, quarantine, or otherwise handle those requests.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'WAF Custom Rules'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'WAF'),
	'Recommended', 'High', 'Medium', 'Available on all plans; the underlying detections and chosen rule action still require their own entitlement. Log requires Enterprise.',
	'(http.host eq "www.example.com" and http.request.uri.path eq "/login" and http.request.method eq "POST" and any(cf.appsec.request.failed_detections[*] in {"waf_credential_check" "waf_score"}))',
	'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.appsec.request.failed_detections/',
	'Introduced 2026-10-09. IDs report failures before custom-rule evaluation; [] means no failures were reported, not that all possible detections ran. Observe len(cf.appsec.request.failed_detections) gt 0 before deciding a scoped fail-closed policy. Other IDs cover content scanning, signatures, and AI prompt detections. The field itself neither enables detectors nor changes their behavior. A Request Header Transform Rule may forward join(cf.appsec.request.failed_detections, ",") to the origin.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Handle Reported Security Detection Failures');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Require Valid JWTs Before Trusting API Identity',
	'Use verified token results to enforce authentication, and separately enforce expected claims and application authorization. Merely presenting a token or header is not authentication.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'API Security'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'API Shield'),
	'Recommended', 'High', 'Medium', 'API Shield JWT validation entitlement and a configured token source, keys, and token configuration.',
	'(http.host eq "api.example.com" and starts_with(http.request.uri.path, "/v1/") and not any(cf.api_gateway.tokens.valid[*] eq "<TOKEN_CONFIGURATION_ID>"))',
	'https://developers.cloudflare.com/api-shield/security/jwt-validation/#waf-custom-rule-examples',
	'Action: Block after observation. Replace the configuration ID and exclude only legitimate token-issuance/refresh endpoints. WAF rules act when expressions are true; legacy API JWT validation rules act when their policy is false. is_jwt_valid() is not available in WAF custom rules. Validate expected issuer/audience and authorization requirements explicitly; rate-limit by a verified stable subject where supported.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Require Valid JWTs Before Trusting API Identity');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Verify Origin TLS with Full (Strict)',
	'Encrypt and authenticate the Cloudflare-to-origin connection with Full (strict), using an unexpired origin certificate that covers the hostname.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'SSL/TLS'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'SSL/TLS'),
	'Recommended', 'High', 'Easy', 'Origin HTTPS listener with a valid matching public-CA or Cloudflare Origin CA certificate.',
	'Set SSL/TLS encryption mode to Full (strict) after verifying every origin presents the correct certificate. Monitor certificate expiry and failures.',
	'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/',
	'Visitor/edge certificates do not replace origin certificates. Full without strict validation does not provide the same server identity verification. Combine strict server verification with origin access restrictions and, where needed, customer-specific Authenticated Origin Pulls.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Verify Origin TLS with Full (Strict)');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes)
SELECT 'Audit Security Bypasses and Narrow Managed Rule Exceptions',
	'Review effective account/zone protection, IP Access Allow entries, Skip rules, and managed-rule exceptions so authenticated and sensitive operations are not silently exempted.',
	'Security', (SELECT category_id FROM Categories WHERE name = 'WAF Custom Rules'), (SELECT feature_id FROM CloudflareFeatures WHERE name = 'WAF'),
	'Recommended', 'High', 'Medium', 'Read access to account and zone security configuration; analytics for confirmed false positives.',
	'Inventory IP Access rules and Skip rules, compare account/zone execute coverage, and scope managed-rule exceptions to the affected hostname, operation, and specific managed rule IDs.',
	'https://developers.cloudflare.com/waf/feature-interoperability/',
	'IP/ASN Allow entries can bypass custom rules, rate limiting, and managed rules and omit the requests from Security Events. Country Allow behaves differently. A Skip does not universally bypass every product; Bot Fight Mode cannot be skipped. Preserve authentication and schema validation. Confirm changes with dry run and traffic observation, and retain rollback versions.'
WHERE NOT EXISTS (SELECT 1 FROM BestPractices WHERE title = 'Audit Security Bypasses and Narrow Managed Rule Exceptions');
