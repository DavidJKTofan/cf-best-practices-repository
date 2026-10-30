-- Editorial taxonomy, not official product/entitlement claims. Hide empty hubs.
-- Intentionally no product assignment or content reclassification on import.
INSERT INTO CatalogTaxa (kind, slug, label) VALUES
	('family', 'application-services', 'Application services'),
	('family', 'cloudflare-one', 'Cloudflare One'),
	('family', 'developer-platform', 'Developer Platform'),
	('family', 'network-services', 'Network services'),
	('family', 'platform-operations', 'Cross-platform operations'),
	('outcome', 'protect-applications', 'Protect applications'),
	('outcome', 'connect-private-applications', 'Connect private applications'),
	('outcome', 'build-reliable-services', 'Build reliable services'),
	('outcome', 'operate-the-platform', 'Operate the platform')
ON CONFLICT (kind, slug) DO NOTHING;
