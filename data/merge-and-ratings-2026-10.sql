-- Merge duplicate practices and fill missing impact ratings, October 2026 (applied to production on 2026-10-04)
--
-- Apply after content-review-2026-10.sql:
--   npx wrangler d1 execute DB --local  --file=./data/merge-and-ratings-2026-10.sql
--   npx wrangler d1 execute DB --remote --file=./data/merge-and-ratings-2026-10.sql
-- Safe to re-run: ratings only fill NULL values and the merge is idempotent.

-- =====================================================================================================
-- 1. Merge #64 "Proxy DNS Records" into #1 (same recommendation). #1 keeps its ID (and permalink).
-- =====================================================================================================

UPDATE BestPractices SET
	title = 'Proxy DNS Records through Cloudflare',
	description = 'Ensure all relevant DNS records (A, AAAA, CNAME) pointing to your origin are proxied (orange-clouded) through Cloudflare to hide origin IPs and apply security and performance features.',
	recommendation_level = 'Mandatory',
	prerequisites = 'Cloudflare must manage the DNS records',
	notes = 'Proxying is required for Cloudflare application services (WAF, rate limiting, bot protection, caching) to apply. Avoid DNS-only (grey-clouded) records unless needed for non-HTTP use cases: they expose the origin IP address.',
	updated_at = CURRENT_TIMESTAMP
WHERE practice_id = 1 AND title <> 'Proxy DNS Records through Cloudflare';

DELETE FROM BestPractices WHERE practice_id = 64 AND title = 'Proxy DNS Records';

-- =====================================================================================================
-- 2. Impact ratings for practices without one
--
-- High:   directly prevents common, high-severity compromise (account takeover, unauthorized access,
--         plaintext or legacy TLS) or has a broad protective effect across the zone.
-- Medium: meaningful risk reduction for a narrower attack surface, abuse or cost reduction, or a strong
--         enabler of detection and response.
-- Low:    visibility-only (Log) rules, coarse or niche controls, or hygiene with little direct security effect.
-- =====================================================================================================

UPDATE BestPractices SET impact_level = 'High', updated_at = CURRENT_TIMESTAMP
WHERE impact_level IS NULL AND practice_id IN (
	17, -- Block Fallthrough API Requests (API Shield)
	20, -- Mitigate Traffic from Managed IP Lists
	25, -- Restrict WordPress (WP) Admin Access
	27, -- Enforce mTLS Authentication
	28, -- Block Revoked mTLS Certificates
	34, -- Use Account Takeover (ATO) Detections
	36, -- Mitigate Logins with Leaked Credentials
	39, -- IP-based Rate Limiting for Logins
	42, -- Rate Limit Logins with Leaked Passwords
	51, -- Set Minimum TLS Version to 1.2
	52  -- Enable Always Use HTTPS
);

UPDATE BestPractices SET impact_level = 'Medium', updated_at = CURRENT_TIMESTAMP
WHERE impact_level IS NULL AND practice_id IN (
	14, -- Allow Verified Bots (WAF Skip)
	15, -- Allow Specific APIs (WAF Skip)
	21, -- Mitigate Tor Traffic
	23, -- Block High Risk Countries (OFAC)
	26, -- Restrict Access to Employee Locations
	29, -- Allow Specific mTLS Client Certificates
	30, -- Challenge Admin JWT Users with High WAF Score
	35, -- Mitigate Disposable Email Signups
	38, -- Mitigate Unauthorized Worker Subrequests
	40, -- Rate Limit Uploads
	44, -- IPv6 Prefix Rate Limiting
	45, -- Client Certificate Rate Limiting (mTLS)
	46, -- JavaScript Detection (JSD) Rate Limiting
	49, -- Use Advanced Certificate Manager (ACM)
	56, -- Use Logpush for Comprehensive Logs
	63  -- Regularly Review Audit Logs
);

UPDATE BestPractices SET impact_level = 'Low', updated_at = CURRENT_TIMESTAMP
WHERE impact_level IS NULL AND practice_id IN (
	16, -- Redirect Specific Traffic via Custom HTML
	18, -- Log Non-Standard HTTP Methods
	24, -- Block Known Bot User-Agents (trivially spoofed)
	31, -- Log Likely Automated Traffic (visibility only)
	33, -- Mitigate IPv6 Traffic (If Unwanted)
	37, -- Implement Time-Based Rules
	43, -- Geography-based Rate Limiting
	50, -- Disable Universal SSL
	53  -- Enable Automatic HTTPS Rewrites
);
