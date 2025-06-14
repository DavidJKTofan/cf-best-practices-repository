-- Comprehensive Initial Data for Cloudflare Best Practices Database
-- Derived from 'General Application Security Recommendations.pdf'

-- Clear existing data (optional, use with caution!)
-- DELETE FROM ZoneImplementations;
-- DELETE FROM BestPractices;
-- DELETE FROM CloudflareFeatures;
-- DELETE FROM Categories;

-- Reset sequences (for SQLite, often handled implicitly or requires specific pragmas/commands not universally supported via basic SQL execution, manage manually if needed)


-- Insert Categories
INSERT INTO Categories (category_id, name, description, display_order) VALUES
(1, 'DNS', 'Settings related to Domain Name System configuration and security.', 1),
(2, 'SSL/TLS', 'Encryption, certificates, and HTTPS settings.', 2),
(3, 'WAF Managed Rules', 'Cloudflare-provided Web Application Firewall rulesets.', 3),
(4, 'WAF Custom Rules', 'User-defined Web Application Firewall rules.', 4),
(5, 'Rate Limiting', 'Rules to control traffic volume and prevent abuse.', 5),
(6, 'Bot Management', 'Settings and rules related to identifying and handling automated traffic.', 6),
(7, 'Origin Protection', 'Securing the connection and identity of the origin server.', 7),
(8, 'Performance', 'Caching, optimization, and speed-related settings.', 8),
(9, 'API Security', 'Practices specifically for securing APIs.', 9),
(10, 'Access Control', 'Restricting access based on user identity, location, or device posture.', 10),
(11, 'Logging & Monitoring', 'Configuration for logging, analytics, and notifications.', 11),
(12, 'Automation & Management', 'Using APIs, Terraform, or SDKs for configuration management.', 12),
(13, 'Client-Side Security', 'Protecting against threats originating from scripts running in the user browser.', 13),
(14, 'Fraud Detection', 'Features to detect fraudulent activities like fake accounts or credential stuffing.', 14),
(15, 'Non-HTTP/S Use Cases', 'Using Cloudflare for protocols other than HTTP/S.', 15),
(16, 'DDoS Protection', 'Cloudflare-provided automatic, unlimited and unmetered DDoS protection.', 16),
(17, 'Cloudflare for SaaS', 'Cloudflare for SaaS allows you to extend the security and performance benefits of Cloudflare network to your customers via their own custom or vanity domains.', 17);

-- Insert Cloudflare Features
INSERT INTO CloudflareFeatures (feature_id, name, feature_url, subscription_level) VALUES
(1, 'DNS', 'https://developers.cloudflare.com/dns/', 'Free'),
(2, 'WAF', 'https://developers.cloudflare.com/waf/', 'Pro'),
(3, 'Rate Limiting Rules', 'https://developers.cloudflare.com/waf/rate-limiting-rules/', 'Pro'),
(4, 'Bot Management', 'https://developers.cloudflare.com/bots/', 'Enterprise'),
(5, 'SSL/TLS', 'https://developers.cloudflare.com/ssl/', 'Free'),
(6, 'API Shield', 'https://developers.cloudflare.com/api-shield/', 'Enterprise'),
(7, 'Page Shield', 'https://developers.cloudflare.com/page-shield/', 'Enterprise'),
(8, 'Turnstile', 'https://developers.cloudflare.com/turnstile/', 'Free'),
(9, 'Cloudflare Access', 'https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/', 'Enterprise'),
(10, 'mTLS', 'https://developers.cloudflare.com/ssl/client-certificates/', 'Enterprise'),
(11, 'Logpush', 'https://developers.cloudflare.com/logs/logpush/', 'Enterprise'),
(12, 'Terraform Provider', 'https://developers.cloudflare.com/terraform/', 'Free'),
(13, 'Cloudflare API', 'https://developers.cloudflare.com/api/', 'Free'),
(14, 'Managed IP Lists', 'https://developers.cloudflare.com/waf/tools/lists/managed-lists/', 'Enterprise'),
(15, 'Advanced Certificate Manager', 'https://developers.cloudflare.com/ssl/edge-certificates/advanced-certificate-manager/', 'Paid Add-On'),
(16, 'Spectrum', 'https://developers.cloudflare.com/spectrum/', 'Enterprise'),
(17, 'Magic Transit', 'https://developers.cloudflare.com/magic-transit/', 'Enterprise'),
(18, 'Workers', 'https://developers.cloudflare.com/workers/', 'Free'),
(19, 'Rules', 'https://developers.cloudflare.com/rules/', 'Free'),
(20, 'Notifications', 'https://developers.cloudflare.com/notifications/', 'Free'),
(21, 'DDoS Protection', 'https://developers.cloudflare.com/ddos-protection/', 'Free'),
(22, 'Cloudflare for SaaS', 'https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/', 'Free'),
(23, 'Argo Smart Routing', 'https://developers.cloudflare.com/argo-smart-routing/', 'Paid Add-On');

-- Insert Best Practices (Examples based on the PDF)

-- ==================
-- General / Setup
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable Proxying for DNS records', 'Ensure all relevant DNS records (A, AAAA, CNAME) are proxied through Cloudflare to benefit from security and performance features.', 'General', 1, 1, 'Recommended', 'High', 'Easy', 'Cloudflare must manage the DNS record', NULL, 'https://developers.cloudflare.com/dns/proxy-status/', 'Proxying (orange-cloud) is essential to apply all security and performance benefits.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable DNSSEC', 'Enable Domain Name System Security Extensions to ensure DNS responses are authentic.', 'Security', 1, 1, 'Recommended', 'High', 'Easy', 'Cloudflare must be Authoritative DNS provider', NULL, 'https://developers.cloudflare.com/dns/dnssec/', 'Assumes Cloudflare is the authoritative DNS provider.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Test Rules with "Log" Action', 'Before applying blocking actions (Block, Managed Challenge, etc.), test WAF or Rate Limiting rules using the "Log" action to observe matches in Security Events.', 'General', 4, 2, 'Recommended', 'Medium', 'Easy', NULL, NULL, 'https://developers.cloudflare.com/ruleset-engine/rules-language/actions/', 'Log action allows you to see what would be blocked without actually blocking it.');


-- ==================
-- WAF Managed Rules
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Deploy WAF Managed Ruleset', 'Enable the core Cloudflare Managed Ruleset for baseline protection against common web threats.', 'Security', 3, 2, 'Recommended', 'High', 'Easy', 'None', NULL, 'https://developers.cloudflare.com/waf/managed-rules/', 'Deploy globally and create exceptions if needed. If you have multiple domains, configure the Account-level WAF.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable Stricter WAF Rule: XSS', 'Enable the specific WAF Managed Rule for XSS, HTML Injection.', 'Security', 3, 2, 'Situational', 'Medium', 'Easy', 'Proxied DNS Records', 'Enable Rule ID: 882b37d6bd5f4bf2a3cdb374d503ded0', 'https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/', NULL);

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable Stricter WAF Rule: Path Anomalies', 'Enable the WAF Managed Rule for URL Path Anomalies (Multiple Slashes, Relative Paths, CR, LF, NULL).', 'Security', 3, 2, 'Situational', 'Medium', 'Easy', 'Proxied DNS Records', 'Enable Rule ID: 6e759e70dc814d90a003f10424644cfb', 'https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/', NULL);

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable Stricter WAF Rule: Large Body', 'Enable the WAF Managed Rule for anomalously large request bodies.', 'Security', 3, 2, 'Situational', 'Medium', 'Easy', 'Proxied DNS Records', 'Enable Rule ID: 7b822fd1f5814e17888ded658480ea8f', 'https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/', 'Mitigates body payloads > processing limit. Add exceptions for your upload endpoints.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable Stricter WAF Rule: Non Standard Port', 'Enable the WAF Managed Rule to block requests targeting non-standard HTTP/S ports (not 80 or 443).', 'Security', 3, 2, 'Situational', 'Medium', 'Easy', 'Proxied DNS Records', 'Enable Rule ID: 8e361ee4328f4a3caf6caf3e664ed6fe', 'https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/', 'Blocks requests to non-standard ports (e.g., 8080, 8443).');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable Stricter WAF Rule: Unusual/Unknown HTTP Method', 'Enable WAF Managed Rules for unusual or unknown HTTP Methods.', 'Security', 3, 2, 'Situational', 'Medium', 'Easy', 'Proxied DNS Records', 'Enable Rule IDs: ab53f93c9b03472ab34a5405d9bdc7d5, 6e2240ffcb87477bbd4881b6fd13142f', 'https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/', NULL);

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable Stricter WAF Rule: Vulnerability Scanners', 'Enable all WAF Managed Rules related to vulnerability scanner activity.', 'Security', 3, 2, 'Situational', 'Medium', 'Easy', 'Proxied DNS Records', 'Refer to WAF Managed Ruleset documentation for specific Rule IDs.', 'https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/', NULL);

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Log Matched Rule Payload', 'If needed for diagnostics, enable payload logging for matched WAF rules.', 'Security', 3, 2, 'Optional', 'Medium', 'Easy', 'Proxied DNS Records', 'Configure via WAF Managed Rules settings.', 'https://developers.cloudflare.com/waf/managed-rules/payload-logging/', 'Log encrypted payloads in Firewall event logs metadata.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Disable Browser Integrity Check (BIC)', 'Consider disabling BIC via Configuration Rules, specifically to prevent potential false positives with APIs or automated traffic.', 'Security', 3, 2, 'Recommended', 'Medium', 'Easy', 'Proxied DNS Records', 'Disable in the Zone Security Settings.', 'https://developers.cloudflare.com/waf/tools/browser-integrity-check/', NULL);

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Deploy OWASP Core Ruleset', 'If required, review and deploy the OWASP Core Ruleset.', 'Security', 3, 2, 'Situational', 'High', 'Easy', 'Proxied DNS Records', 'Enable via the Zone Security Settings.', 'https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/', 'OWASP Rulesets are prone to false positives. Add exceptions for Zaraz endpoint if used and any other sensitive path.');


-- ==================
-- WAF Custom Rules
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Allow Verified Bots (WAF Skip)', 'Create a WAF Custom Rule with a SKIP action to explicitly allow known good bots like search engine crawlers.', 'Security', 4, 2, 'Recommended', NULL, 'Medium', NULL, '`(cf.bot_management.verified_bot) or (cf.verified_bot_category eq "Search Engine Crawler")`', 'https://developers.cloudflare.com/waf/custom-rules/use-cases/allow-traffic-from-verified-bots/', 'Place this rule early, at the top. The Bot Management fields require an Enterprise Bot Management subscription.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Allow Specific APIs (WAF Skip)', 'Create a WAF Custom Rule with a SKIP action to allow trusted API traffic (own or partner APIs), using specific match criteria (hostname, path, method, headers, etc.).', 'Security', 4, 2, 'Recommended', NULL, 'Medium', NULL, '`(http.host eq "api.example.com" and http.request.uri.path contains "/api/resource" and http.request.method eq "GET" and any(http.request.headers["x-api-key"][*] == "SECRET_KEY"))`', 'https://developers.cloudflare.com/waf/custom-rules/skip/', 'Be as specific as possible. Ultimate goal should be positive security model with Cloudflare API Shield subscription.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Redirect Specific Traffic via Custom HTML', 'Use a WAF Custom Rule with Block action and Custom HTML response type to redirect certain requests (e.g., non-verified bots from a specific country).', 'Security', 4, 2, 'Situational', NULL, 'Medium', NULL, '`(ip.geoip.country eq "US" and not cf.bot_management.verified_bot)`. Action: Block, Response Type: Custom HTML, Response Code: 418, Body: `<meta http-equiv=refresh content=''0; URL=http://example.com/''>`', 'https://developers.cloudflare.com/waf/custom-rules/create-dashboard/#configure-a-custom-response-for-blocked-requests', 'You can customize the response for blocked requests, even inserting your own brand.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Block Fallthrough API Requests (API Shield)', 'If using API Shield with a positive security model, create a WAF rule to block requests to API hostnames that do not match any saved and defined operation/endpoint.', 'Security', 9, 6, 'Recommended', NULL, 'Easy', NULL, '`(http.host in {"api.example.com"} and cf.api_gateway.fallthrough_detected)`', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.api_gateway.fallthrough_detected/', 'Enforces positive security model. Requires a Cloudflare API Shield subscription.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Log Non-Standard HTTP Methods', 'Create a WAF Custom Rule with Log action to gain visibility into non-standard HTTP methods being used (POST, PUT, DELETE etc.) on specific endpoints.', 'Security', 4, 2, 'Situational', NULL, 'Easy', NULL, '`(http.request.method in {"POST" "PURGE" "PUT" "HEAD" "OPTIONS" "DELETE" "PATCH"})`', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.method/', NULL);

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Mitigate Likely Malicious Requests (WAF Attack Score)', 'Create a WAF Custom Rule to challenge or block requests with a low WAF Attack Score (indicating likely SQLi, XSS, RCE).', 'Security', 4, 2, 'Recommended', NULL, 'Easy', NULL, '`(cf.waf.score lt 20)` - Example threshold, adjust as needed. Action: Managed Challenge or Block.', 'https://developers.cloudflare.com/waf/custom-rules/use-cases/block-attack-score/', 'The WAF Attack Score manages to detect different patterns of attacks, providing dynamic security.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Mitigate Traffic from Managed IP Lists', 'Create WAF Custom Rules to block or challenge traffic based on Cloudflare Managed IP Lists (Anonymizers, Botnets, Malware, Open Proxies, VPNs).', 'Security', 4, 14, 'Recommended', NULL, 'Easy', NULL, '`(ip.src in $cf.botnets_command_and_control) or (ip.src in $cf.malware)`', 'https://developers.cloudflare.com/waf/tools/lists/managed-lists/', 'Typically block Botnets/Malware. Consider mitigating specific VPN ASNs manually if needed.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Mitigate Tor Traffic (WAF Rule)', 'Create a WAF Custom Rule to block or challenge traffic originating from the Tor network if it is unwanted.', 'Security', 4, 2, 'Situational', NULL, 'Easy', NULL, '`(ip.geoip.continent eq "T1")`', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.continent/', 'Ensure Onion Routing feature is disabled in the Zone Network Settings if blocking Tor.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Mitigate Unwanted ASNs', 'Create WAF Custom Rules (preferably using Lists) to block or challenge traffic from specific Autonomous System Numbers (ASNs), such as unwanted cloud providers or specific networks.', 'Security', 4, 2, 'Situational', NULL, 'Easy', NULL, '`(ip.geoip.asnum in {14618 16509})`', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/ip.src.asnum/', 'Use Lists for easier management.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Block High Risk Countries (OFAC)', 'Create a WAF Custom Rule to block traffic from countries identified as high-risk or subject to sanctions (e.g., OFAC list).', 'Security', 4, 2, 'Situational', NULL, 'Easy', NULL, '`(ip.geoip.country in {"BY" "CU" "IR" "KP" ...})`', 'https://sanctionssearch.ofac.treas.gov/', 'The List requires updating based on current sanctions lists. Use the Cloudflare API, SDK, or Terraform for automation.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Block Known Bot User-Agents', 'Create a WAF Custom Rule to block requests with User-Agent strings commonly used by unwanted bots (e.g., curl, go-http-client, empty).', 'Security', 4, 2, 'Situational', NULL, 'Easy', NULL, '`(http.user_agent contains "curl") or (http.user_agent contains "go-http-client") or (http.user_agent eq "")`', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.user_agent/', 'Be careful with over-blocking some User-Agents.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Restrict WordPress (WP) Admin Access (IP/Access)', 'For WordPress (WP) sites, restrict access to /wp-admin using a WAF Custom Rule matching specific source IPs (preferably via List) or (highly recommended) implement Zero Trust using Cloudflare Access.', 'Security', 10, 2, 'Recommended', NULL, 'Easy', NULL, '`(not ip.src in $allowed_ips and http.request.uri.path contains "/wp-admin")`. Action: Block', 'https://developers.cloudflare.com/waf/tools/lists/', 'Preferably use Cloudflare Access for a Zero Trust approach instead.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Restrict Access to Employee Locations (IP/Access)', 'For internal portals, restrict access using a WAF Custom Rule to only allow countries where employees are located, or preferably (and highly recommended) use Cloudflare Access.', 'Security', 10, 2, 'Recommended', NULL, 'Easy', NULL, '`(not ip.geoip.country in {"US" "GB"})`. Action: Block.', 'https://developers.cloudflare.com/waf/custom-rules/use-cases/allow-traffic-from-specific-countries/', 'Be specific with your rules. Consider mTLS as an alternative, however, it is strongly recommended to use Cloudflare Access instead.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enforce mTLS Authentication', 'For specific hostnames requiring mutual TLS, create a WAF Custom Rule to block requests without a valid, verified client certificate.', 'Security', 10, 10, 'Recommended', NULL, 'Easy', NULL, '`(http.host in {"mtls.example.com" "mtls2.example.com"} and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))`', 'https://developers.cloudflare.com/learning-paths/mtls/mtls-app-security/related-features/#waf-for-client-certificates', 'Follow the best practices for mTLS configuration. Ensure the client certificate is verified and not expired.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Block Revoked mTLS Certificates', 'Enhance mTLS by also blocking requests presenting a revoked client certificate.', 'Security', 10, 10, 'Recommended', NULL, 'Easy', NULL, '`(http.host in {"mtls.example.com"} and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))`. Action: Block.', 'https://developers.cloudflare.com/learning-paths/mtls/mtls-app-security/related-features/#certificate-revocation', 'Follow the best practices for mTLS configuration. Ensure the client certificate is verified and not expired.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Allow Specific mTLS Client Certificates', 'For granular control, create WAF rules to allow mTLS access only for specific client certificate serial numbers or even the issuer Subject Key Identifier (SKI) hash on certain hostnames.', 'Security', 10, 10, 'Situational', NULL, 'Easy', NULL, '`(http.host in {"mtls.example.com"} and cf.tls_client_auth.cert_serial ne "SPECIFIC_SERIAL_NUMBER")`', 'https://developers.cloudflare.com/api-shield/security/mtls/configure/#create-an-mtls-rule', 'Review the available mTLS fields for Rules.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Challenge Admin JWT Users with High WAF Score', 'For APIs using JWT, create a WAF Custom Rule to challenge requests where the JWT indicates an admin user AND the WAF Attack Score is high.', 'Security', 9, 2, 'Situational', NULL, 'Easy', NULL, '`(lookup_json_string(http.request.jwt.claims[0], "user") eq "admin" and cf.waf.score lt 40)`. Action: Block.', 'https://developers.cloudflare.com/waf/custom-rules/use-cases/check-jwt-claim-to-protect-admin-user/', 'Requires parsing JWT claims and using the Cloudflare API Shield JSON Web Tokens (JWT) Validation feature.');


-- ==================
-- Bot Management
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Log Likely Automated Traffic (Bot Score)', 'Create a WAF Custom Rule with Log action to gain visibility into traffic Cloudflare classifies as likely automated based on Bot Score.', 'Security', 6, 4, 'Recommended', NULL, 'Easy', NULL, '`(cf.bot_management.score lt 30)`', 'https://developers.cloudflare.com/waf/custom-rules/use-cases/challenge-bad-bots/', 'Adjust threshold as needed. Requires a Cloudflare Enterprise Bot Management subscription.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enforce JavaScript Detections (JSD)', 'For critical HTML sites, enforce JSD by challenging requests that fail the JSD check.', 'Security', 6, 4, 'Situational', NULL, 'Easy', NULL, '`(http.request.uri.path eq "/critical/path" and not cf.bot_management.js_detection.passed)`. Action: Block.', 'https://developers.cloudflare.com/bots/additional-configurations/javascript-detections/#enforcing-execution-of-javascript-detections', 'Requires a Cloudflare Enterprise Bot Management subscription. JSD only injects on HTML responses and cannot run on the first request.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Mitigate IPv6 Traffic (If Unwanted)', 'If IPv6 is not needed or desired, create a WAF Custom Rule to block or challenge traffic from IPv6 source addresses.', 'Security', 4, 2, 'Situational', NULL, 'Easy', NULL, '`(ip.src in {::/0})`. Action: Block.', 'https://developers.cloudflare.com/network/ipv6-compatibility/', 'Consider disabling IPv6 compatibility in Zone Network Settings as well.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Use Account Takeover Detections', 'Leverage Cloudflare Enterprise Bot Management Detection IDs in WAF or Rate Limiting rules to mitigate predictable bot behavior like login failures.', 'Security', 6, 4, 'Recommended', NULL, 'Easy', NULL, '`(any(cf.bot_management.detection_ids[*] eq 201326592) and http.request.uri.path contains "/login")`', 'https://developers.cloudflare.com/bots/additional-configurations/detection-ids/', 'Requires a Cloudflare Enterprise Bot Management subscription. Consider also implementing Turnstile, a CAPTCHA alternative.');


-- ==================
-- Fraud Detection
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Mitigate Disposable Email Signups', 'Use Cloudflare Fraud Detection features via WAF rules to block, challenge, log, or rate limit signups using known disposable email domains.', 'Security', 14, 2, 'Recommended', NULL, 'Easy', NULL, '`(http.host eq "www.example.com" and http.request.uri.path eq "/api/user/create" and http.request.method in {"POST"} and cf.fraud_detection.disposable_email)`', 'https://blog.cloudflare.com/cloudflare-fraud-detection/', 'Cloudflare Fraud Detection is in early access. Contact your account team.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Mitigate Logins with Leaked Credentials', 'Use Leaked Credentials Detection via WAF or Rate Limiting rules to challenge or block login attempts using credentials (passwords) known to be leaked (HIBP), or forward this info to the origin server to trigger password resets for specific users.', 'Security', 14, 2, 'Recommended', NULL, 'Easy', NULL, '`(cf.waf.credential_check.password_leaked and http.request.uri.path contains "/api/login" and http.request.method in {"POST"})`', 'https://developers.cloudflare.com/waf/detections/leaked-credentials/', 'Applies to detected authentication events. Create your own custom detection location.');


-- ==================
-- Advanced Rules / Time-based
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Implement Time-Based Rules', 'Use the `http.request.timestamp.sec` field in WAF rules to apply logic based on specific time periods (e.g., block POSTs during maintenance window).', 'Security', 4, 2, 'Situational', NULL, 'Easy', NULL, '`(http.request.method eq "POST" and http.request.timestamp.sec gt 1712779200 and http.request.timestamp.sec lt 1712782800)`', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/http.request.timestamp.sec/', 'The timestamp is represented in UNIX time and consists of a 10-digit value.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Mitigate Unauthorized Worker Subrequests', 'Prevent abuse from other Cloudflare Workers by using the WAF rules to block subrequests originating from unknown Cloudflare Workers.', 'Security', 4, 18, 'Situational', NULL, 'Easy', NULL, '`not (cf.worker.upstream_zone in {"" "you-zone.com"})`', 'https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-worker', 'Review the documentation on `CF-Connecting-IP` HTTP Request Header in Worker subrequests.');


-- ==================
-- Rate Limiting Rules
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('IP-based Rate Limiting for Logins', 'Protect login endpoints by creating a Rate Limiting rule that tracks and limits login attempts per IP address over a time window.', 'Security', 5, 3, 'Recommended', NULL, 'Easy', NULL, 'Characteristics: IP Address. Match `(http.host eq "www.cf-testing.com" and http.request.uri.path eq "/login" and http.request.method eq "POST")`. Action: Block or Log.', 'https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/', 'Adjust the rate counter based on expected traffic.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Rate Limit Uploads', 'Prevent excessive uploads by creating a Rate Limiting rule based on IP address or session, targeting POST/PUT/PATCH methods on upload endpoints.', 'Security', 5, 3, 'Situational', NULL, 'Easy', NULL, 'Characteristics: IP Address. Match `(http.host eq "www.cf-testing.com" and http.request.uri.path eq "/upload" and http.request.method in {"POST" "PUT" "PATCH"})`. Action: Block or Throttle.', 'https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/', 'Adjust the rate counter based on expected traffic.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Rate Limit Credential Stuffing', 'Mitigate credential stuffing by rate limiting login attempts based on session (cookie/header) or IP or other characteristics, potentially with lower thresholds than general login limiting.', 'Security', 5, 3, 'Recommended', NULL, 'Easy', NULL, 'Characteristics: IP + Session Cookie/Header. Match `(http.host eq "www.cf-testing.com" and http.request.uri.path eq "/login" and http.request.method eq "POST")`. Action: Block or Throttle.', 'https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/#protecting-against-credential-stuffing', 'Requires a Cloudflare Advanced Rate Limiting subscription. Consider also implementing Turnstile, a CAPTCHA alternative.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Rate Limit Logins with Leaked Passwords', 'Create a Rate Limiting rule specifically targeting login attempts (authentication events) detected using leaked passwords (HIBP).', 'Security', 5, 3, 'Recommended', NULL, 'Easy', NULL, 'Characteristics: IP or Session Cookie/Header. Match `(http.request.uri.path contains "/login" and cf.waf.credential_check.password_leaked)`.', 'https://developers.cloudflare.com/waf/detections/leaked-credentials/examples/', 'Consider also implementing Turnstile, a CAPTCHA alternative.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Geography-based Rate Limiting', 'If certain countries generate unexpected amounts of traffic, apply rate limiting based on the IP address.', 'Security', 5, 3, 'Situational', NULL, 'Easy', NULL, 'Characteristics: IP Address. Match `ip.geoip.country in {"DE" "ES"}`.', 'https://developers.cloudflare.com/waf/rate-limiting-rules/use-cases/', 'Adjust the rate counter based on expected traffic.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('IPv6 Prefix Rate Limiting', 'Protect against abuse from entire IPv6 prefixes by rate limiting using the `cidr6()` function in custom characteristics.', 'Security', 5, 3, 'Situational', NULL, 'Easy', NULL, 'Match `(http.host eq "www.cf-testing.com" and http.request.uri.path eq "/login" and http.request.method eq "POST")`. Custom Characteristic: `cidr6(ip.src, 48)` (adjust prefix length as needed).', 'https://developers.cloudflare.com/ruleset-engine/rules-language/functions/#cidr6', 'Requires a Cloudflare Advanced Rate Limiting subscription. Adjust the rate counter based on expected traffic.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Client Certificate Rate Limiting (mTLS)', 'Prevent abuse of compromised mTLS certificates or devices by rate limiting requests based on the client certificate fingerprint.', 'Security', 5, 10, 'Situational', NULL, 'Easy', NULL, '`(http.host in {"mtls.example.com" "mtls2.example.com"} and cf.tls_client_auth.cert_verified)`. Header value Of Characteristic: `Cf-Client-Cert-Sha256` (SHA256 fingerprint of the certificate).', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.tls_client_auth.cert_fingerprint_sha256/', 'Implement mTLS best practices. Other mTLS specific fields are also available.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('JavaScript Detection (JSD) Rate Limiting', 'Rate limit based on repeated failures of JavaScript Detection (JSD) challenges.', 'Security', 5, 4, 'Situational', NULL, 'Easy', NULL, '`not cf.bot_management.js_detection.passed`. Characteristic: IP Address. Increment Counter: `(any(http.response.headers["content-type"][*] contains "text/html"))`.', 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.js_detection.passed/', 'Requires Cloudflare Enterprise Bot Management subscription. JSD only injects on HTML responses and cannot run on the first request. Consider also implementing Turnstile, a CAPTCHA alternative.');


-- ==================
-- Turnstile
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Implement Turnstile on Forms', 'Use Cloudflare Turnstile (managed mode recommended) on login, signup, or other forms to distinguish humans from bots without complex CAPTCHAs.', 'Security', 6, 8, 'Recommended', NULL, 'Easy', NULL, 'Requires client-side integration and server-side validation using Siteverify API.', 'https://developers.cloudflare.com/turnstile/tutorials/implicit-vs-explicit-rendering/', 'Integrate Turnstile with the WAF and Enterprise Bot Management by enabling the Pre-Clearance Cookie.');


-- ==================
-- Page Shield
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Monitor JavaScript Dependencies with Cloudflare Page Shield', 'Use Page Shield to monitor client-side JavaScript dependencies and get alerted to changes or malicious scripts.', 'Security', 13, 7, 'Recommended', NULL, 'Easy', NULL, 'Enable Page Shield monitoring and configure alerts.', 'https://developers.cloudflare.com/page-shield/detection/monitor-connections-scripts/', 'Cloudflare Enterprise Page Shield Add-On is relevant for PCI DSS compliance, specifically client-side protection. Create Policies for a positive security model.');


-- ==================
-- SSL/TLS
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Use Advanced Certificate Manager (ACM)', 'Prefer ACM over Universal SSL for more control over certificates, hostnames, and settings.', 'Security', 2, 15, 'Recommended', NULL, 'Easy', NULL, NULL, 'https://developers.cloudflare.com/ssl/edge-certificates/advanced-certificate-manager/', 'Review the different SSL and TLS settings, as well as customization requirements. Those seeking PCI compliance and granular customization over cipher suites should review the developer documentations, as well as the features TLS 1.3, Minimum TLS Version (TLS 1.2 is the recommended option here), Automatic HTTPS Rewrites, Always Use HTTPS (or preferably disable HTTP plaintext altogether).');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Disable Universal SSL (and use ACM or Custom Certificates instead)', 'If using ACM or Custom Certificates, disable the Universal SSL certificate for the Zone.', 'Security', 2, 5, 'Situational', NULL, 'Easy', NULL, NULL, 'https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/', 'Verify that there is always a valid and active Edge Certificate for your hostnames.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Set Minimum TLS Version to 1.2', 'Configure Cloudflare to only allow TLS 1.2 or higher connections for improved security.', 'Security', 2, 5, 'Recommended', NULL, 'Easy', NULL, NULL, 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/', 'Enable TLS 1.3. Recommended option for compliance and security.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable Always Use HTTPS', 'Force all visitor connections to use HTTPS.', 'Security', 2, 5, 'Mandatory', NULL, 'Easy', NULL, NULL, 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/', 'Consider also enabling HSTS as well. Preferably disable plaintext HTTP entirely.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable Automatic HTTPS Rewrites', 'Allow Cloudflare to automatically rewrite HTTP links to HTTPS in HTML source code.', 'Security', 2, 5, 'Recommended', NULL, 'Easy', NULL, NULL, 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/automatic-https-rewrites/', 'Helps prevent mixed content warnings. Review your application source code.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable HTTP/2 and HTTP/3', 'Enable modern HTTP protocols (HTTP/2, HTTP/3 QUIC) for performance and security improvements.', 'Performance', 8, 5, 'Recommended', NULL, 'Easy', NULL, NULL, 'https://developers.cloudflare.com/speed/optimization/protocol/http3/', 'Review the Speed Optimization features.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enable HTTP/2 to Origin', 'Allow Cloudflare to use HTTP/2 when connecting to your origin servers if supported.', 'Performance', 8, 5, 'Recommended', NULL, 'Easy', NULL, NULL, 'https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/', 'Requires origin server support for HTTP/2. Adjust the connection multiplexing (request pooling).');


-- ==================
-- Logging & Monitoring
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Use Logpush for Comprehensive Logs', 'Configure Logpush to send detailed Firewall events, HTTP request, or other logs to a storage service (R2, S3) or SIEM.', 'Security', 11, 11, 'Recommended', NULL, 'Easy', NULL, NULL, 'https://developers.cloudflare.com/logs/about/', 'Logpush is strongly recommended for long-term storage and non-sampled logs.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Set Up Notifications', 'Configure Cloudflare Notifications for relevant events (security events, certificate expiry, DDoS attacks, etc.).', 'Security', 11, NULL, 'Recommended', NULL, 'Easy', NULL, NULL, 'https://developers.cloudflare.com/notifications/', 'Review available Notifications and configure them based on your needs. Consider using the Cloudflare API or Terraform for automation.');


-- ==================
-- Automation & Management
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference) VALUES
('Use Terraform for Infrastructure as Code (IaC)', 'Manage Cloudflare configurations using the Cloudflare Terraform Provider for automation, version control, and consistency.', 'General', 12, 12, 'Recommended', 'High', 'Medium', 'Knowledge of Terraform, version control systems like Git', NULL, 'https://developers.cloudflare.com/terraform/');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference) VALUES
('Use Cloudflare API or SDKs for Automation', 'Leverage the Cloudflare API or official SDKs for custom automation scripts and integrations.', 'General', 12, 13, 'Recommended', 'Medium', 'Medium', 'Prior knowledge in SDKs or programming is recommended', NULL, 'https://developers.cloudflare.com/fundamentals/api/reference/sdks/');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Follow Principle of Least Privilege for Users and Tokens', 'Assign users and API Tokens only the minimum required permissions using specific Roles and scoped tokens.', 'Security', 12, 13, 'Mandatory', NULL, 'Medium', NULL, NULL, 'https://developers.cloudflare.com/fundamentals/setup/manage-members/', 'Use Roles for Dashboard UI access and configure API Token permissions separately. Leverage Account Owned Tokens. Enterprise customers can also configure Single-Sign-On (SSO) for the Cloudflare Dashboard.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Enforce Multi-Factor Authentication (MFA)', 'Require MFA for all users accessing the Cloudflare dashboard.', 'Security', 12, NULL, 'Mandatory', NULL, 'Easy', NULL, NULL, 'https://developers.cloudflare.com/fundamentals/setup/account/account-security/2fa/', 'MFA is often a compliance requirement. Enterprise customers can also configure Single-Sign-On (SSO) for the Cloudflare Dashboard.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Integrate Single Sign-On (SSO)', 'If applicable, integrate your identity provider (IdP) with Cloudflare for SSO dashboard access.', 'Security', 12, NULL, 'Recommended', NULL, 'Complex', 'Requires a valid Identity Provider (IdP)', NULL, 'https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/dash-sso-apps/', 'Review the Cloudflare SSO documentation for best practices, especially backups (break-glass).');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference) VALUES
('Regularly Review Audit Logs', 'Periodically review Cloudflare Audit Logs to monitor configuration changes and detect suspicious activity.', 'Security', 11, NULL, 'Recommended', NULL, 'Easy', NULL, NULL, 'https://developers.cloudflare.com/fundamentals/setup/account/account-security/review-audit-logs/');


-- ==================
-- Origin Protection
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Proxy DNS Records', 'Ensure all relevant DNS records pointing to your origin are proxied (orange-clouded) through Cloudflare to hide origin IPs and apply application services.', 'Security', 7, NULL, 'Mandatory', 'High', 'Easy', 'Cloudflare must manage the DNS records', NULL, 'https://developers.cloudflare.com/dns/proxy-status/', 'Avoid grey-clouding unless for specific non-HTTP use cases and really necessary.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Use Authenticated Origin Pulls (mTLS)', 'Configure mTLS between Cloudflare edge and your origin server to ensure requests are genuinely from your Cloudflare account.', 'Security', 7, 10, 'Recommended', 'High', 'Complex', 'Access to origin server configuration, valid SSL/TLS certificate', NULL, 'https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/', 'Review the Cloudflare documentation and follow the best practices.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Rotate Origin IPs After Onboarding', 'After migrating to Cloudflare and proxying records, change your origin server IP addresses.', 'Security', 7, NULL, 'Recommended', 'High', 'Medium', 'Access to infrastructure management, DNS control', NULL, 'https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/', 'Review the Cloudflare documentation and follow the best practices.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Use Transform Rules for Security Headers', 'Leverage Managed Transforms or create custom Transform Rules to add or modify security response headers.', 'Security', 7, 2, 'Recommended', 'Medium', 'Medium', 'Understanding of HTTP security headers', NULL, 'https://developers.cloudflare.com/rules/transform/managed-transforms/reference/', 'Use Cloudflare Snippets for more customizable HTTP header modifications or other custom logics.');


-- ==================
-- API Security
-- ==================
INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Implement API Schema Validation', 'Use API Shield to upload your API schema (OpenAPI) and enforce validation on incoming requests.', 'Security', 9, 6, 'Recommended', 'High', 'Complex', 'Valid OpenAPI schema document, API Shield subscription', NULL, 'https://developers.cloudflare.com/api-shield/security/schema-validation/', 'The main goal should be to implement a positive security model for your APIs.');

INSERT INTO BestPractices (title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level, prerequisites, expressions_configuration_details, source_reference, notes) VALUES
('Use API Shield Sequence Mitigation', 'Define expected sequences of API calls and use Cloudflare API Shield Sequence Mitigation to detect and block out-of-order requests.', 'Security', 9, 6, 'Recommended', 'High', 'Complex', NULL, NULL, 'https://developers.cloudflare.com/api-shield/security/sequence-mitigation/', 'Review the Cloudflare documentation.');

-- End of comprehensive initial data --