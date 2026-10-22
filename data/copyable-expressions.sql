-- Apply migration 0004 first. Re-runnable editorial separation of existing examples.
-- No rules, actions, thresholds, entitlements, prerequisites, or IDs are changed.
-- Sources are the existing source_reference URLs reviewed in content-review-2026-10-15.md.
-- These explicitly reviewed records already contain only a Rules expression.
UPDATE BestPractices
SET expression = expressions_configuration_details, updated_at = CURRENT_TIMESTAMP
WHERE practice_id IN (
	14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 71, 74, 77, 78, 79, 86, 89, 90, 92,
	98, 99, 100, 103, 104, 105
)
AND expression IS NULL AND expressions_configuration_details IS NOT NULL;

-- Explicit match expressions from composite rate-limiting examples. Keep the full
-- configuration (including counting expressions and plan caveats) alongside them.
-- The containment guard avoids attaching an example to content that has since changed.
WITH examples(practice_id, expression) AS (VALUES
	(39, '(http.host eq "www.example.com" and http.request.uri.path eq "/login" and http.request.method eq "POST")'),
	(40, '(http.host eq "www.example.com" and http.request.uri.path eq "/upload" and http.request.method in {"POST" "PUT" "PATCH"})'),
	(41, '(http.host eq "www.example.com" and http.request.uri.path eq "/login" and http.request.method eq "POST")'),
	(42, '(http.host eq "www.example.com" and http.request.uri.path eq "/login" and http.request.method eq "POST" and cf.waf.credential_check.username_and_password_leaked)'),
	(43, 'ip.src.country in {"DE" "ES"}'),
	(44, '(http.host eq "www.example.com" and http.request.uri.path eq "/login" and http.request.method eq "POST")'),
	(45, '(http.host eq "mtls.example.com" and cf.tls_client_auth.cert_verified and not cf.tls_client_auth.cert_revoked)'),
	(46, '(http.host eq "www.example.com" and http.request.uri.path eq "/account/overview" and http.request.method eq "GET" and not cf.bot_management.js_detection.passed and not cf.bot_management.verified_bot)'),
	(93, '(http.host eq "www.example.com" and http.request.uri.path in {"/api/otp/validate" "/account/verify" "/password-reset"} and http.request.method eq "POST")'),
	(94, '(http.host eq "www.example.com" and starts_with(http.request.uri.path, "/catalog/") and http.request.method eq "GET" and not cf.client.bot)'),
	(95, '(http.host eq "api.example.com" and starts_with(http.request.uri.path, "/v1/") and any(cf.api_gateway.tokens.valid[*] eq "<TOKEN_CONFIGURATION_ID>"))'),
	(96, '(http.host eq "www.example.com" and http.request.uri.path eq "/merchant" and http.request.uri.query contains "action=lookup_price")'),
	(97, '(http.host eq "api.example.com" and http.request.uri.path eq "/graphql" and http.request.method eq "POST" and http.request.body.raw contains "createReview")')
)
UPDATE BestPractices AS bp
SET expression = examples.expression, updated_at = CURRENT_TIMESTAMP
FROM examples
WHERE bp.practice_id = examples.practice_id AND bp.expression IS NULL
	AND instr(bp.expressions_configuration_details, examples.expression) > 0;
