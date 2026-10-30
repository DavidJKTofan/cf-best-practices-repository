-- Public registry labels only, not feature/seat/plan entitlements or legacy conversion.
INSERT INTO CatalogTaxa (kind, slug, label) VALUES
	('product', 'access', 'Access'),
	('product', 'tunnel', 'Cloudflare Tunnel'),
	('product', 'workers', 'Workers'),
	('product', 'd1', 'D1')
ON CONFLICT (kind, slug) DO NOTHING;
