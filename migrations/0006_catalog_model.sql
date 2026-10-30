-- Additive Phase 2 model. Legacy rows remain authoritative until explicitly converted.
-- Never put drafts, unpublished revisions, or receipts into public seed exports.
CREATE TABLE CatalogTaxa (
	kind TEXT NOT NULL CHECK (kind IN ('family', 'product', 'outcome')),
	slug TEXT NOT NULL CHECK (length(slug) BETWEEN 1 AND 80),
	label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 200),
	PRIMARY KEY (kind, slug)
);
CREATE TABLE CatalogTaxonAliases (
	kind TEXT NOT NULL,
	alias TEXT NOT NULL CHECK (length(alias) BETWEEN 1 AND 80),
	slug TEXT NOT NULL,
	PRIMARY KEY (kind, alias),
	FOREIGN KEY (kind, slug) REFERENCES CatalogTaxa(kind, slug)
);
CREATE TABLE CatalogEntries (
	practice_id INTEGER PRIMARY KEY AUTOINCREMENT CHECK (practice_id BETWEEN 1 AND 2147483647),
	legacy_practice_id INTEGER UNIQUE REFERENCES BestPractices(practice_id),
	published_revision_id INTEGER,
	CHECK (legacy_practice_id IS NULL OR legacy_practice_id = practice_id),
	FOREIGN KEY (practice_id, published_revision_id) REFERENCES CatalogPublications(practice_id, revision_id)
);
CREATE TABLE CatalogRevisions (
	revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
	practice_id INTEGER NOT NULL REFERENCES CatalogEntries(practice_id),
	schema_version INTEGER NOT NULL CHECK (schema_version = 1),
	content_type TEXT NOT NULL CHECK (content_type IN ('recommendation', 'rule-policy', 'reference-architecture', 'implementation-guide')),
	title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 500),
	summary TEXT NOT NULL CHECK (length(summary) BETWEEN 1 AND 500),
	primary_family TEXT NOT NULL,
	primary_family_kind TEXT NOT NULL DEFAULT 'family' CHECK (primary_family_kind = 'family'),
	applicability_json TEXT NOT NULL CHECK (json_valid(applicability_json) AND json_type(applicability_json) = 'object'),
	body_json TEXT NOT NULL CHECK (length(CAST(body_json AS BLOB)) <= 65536 AND json_valid(body_json) AND json_type(body_json) = 'object'),
	evidence TEXT NOT NULL CHECK (evidence IN ('unreviewed', 'public-docs', 'lab-tested')),
	maturity TEXT NOT NULL CHECK (maturity IN ('unknown', 'ga', 'beta', 'early-access', 'announcement-only')),
	modified_at TEXT,
	fact_verified_at TEXT,
	review_due_at TEXT,
	UNIQUE (practice_id, revision_id),
	FOREIGN KEY (primary_family_kind, primary_family) REFERENCES CatalogTaxa(kind, slug)
);
CREATE TABLE CatalogRevisionTaxa (
	revision_id INTEGER NOT NULL REFERENCES CatalogRevisions(revision_id),
	kind TEXT NOT NULL,
	slug TEXT NOT NULL,
	PRIMARY KEY (revision_id, kind, slug),
	FOREIGN KEY (kind, slug) REFERENCES CatalogTaxa(kind, slug)
);
CREATE INDEX idx_catalog_revision_taxa_lookup ON CatalogRevisionTaxa(kind, slug, revision_id);
CREATE TABLE CatalogRevisionSources (
	revision_id INTEGER NOT NULL REFERENCES CatalogRevisions(revision_id),
	position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 15),
	url TEXT NOT NULL CHECK (length(url) BETWEEN 1 AND 1000 AND (url LIKE 'https://%' OR url LIKE 'http://%')),
	title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 500),
	PRIMARY KEY (revision_id, position)
);
-- A publication freezes the revision and its relationships. The entry pointer, not
-- MAX(revision_id), chooses the public snapshot. Publication commands are Phase 4.
CREATE TABLE CatalogPublications (
	practice_id INTEGER NOT NULL,
	revision_id INTEGER NOT NULL UNIQUE,
	published_at TEXT NOT NULL,
	PRIMARY KEY (practice_id, revision_id),
	FOREIGN KEY (practice_id, revision_id) REFERENCES CatalogRevisions(practice_id, revision_id)
);
CREATE TABLE CatalogDrafts (
	practice_id INTEGER PRIMARY KEY REFERENCES CatalogEntries(practice_id),
	version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
	content_json TEXT NOT NULL CHECK (length(CAST(content_json AS BLOB)) <= 65536 AND json_valid(content_json)),
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_catalog_revisions_entry ON CatalogRevisions(practice_id, revision_id);
CREATE TRIGGER catalog_identity_immutable BEFORE UPDATE OF practice_id, legacy_practice_id ON CatalogEntries
WHEN NEW.practice_id IS NOT OLD.practice_id OR NEW.legacy_practice_id IS NOT OLD.legacy_practice_id
BEGIN SELECT RAISE(ABORT, 'Catalog identity is immutable'); END;
CREATE TRIGGER catalog_identity_insert_immutable BEFORE INSERT ON CatalogEntries
WHEN EXISTS (SELECT 1 FROM CatalogEntries WHERE practice_id = NEW.practice_id AND legacy_practice_id IS NOT NEW.legacy_practice_id)
BEGIN SELECT RAISE(ABORT, 'Catalog identity is immutable'); END;

-- Legacy conversion needs an explicit v1 projection plus document parity (later
-- phases). Do not allow a pointer flip to silently split v1/v2 authority now.
CREATE TRIGGER catalog_legacy_conversion_gate BEFORE UPDATE OF published_revision_id ON CatalogEntries
WHEN NEW.legacy_practice_id IS NOT NULL AND NEW.published_revision_id IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'Legacy conversion requires a reviewed compatibility adapter'); END;
CREATE TRIGGER catalog_legacy_conversion_insert_gate BEFORE INSERT ON CatalogEntries
WHEN NEW.legacy_practice_id IS NOT NULL AND NEW.published_revision_id IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'Legacy conversion requires a reviewed compatibility adapter'); END;
CREATE TRIGGER catalog_publication_relationships BEFORE INSERT ON CatalogPublications
WHEN NOT EXISTS (SELECT 1 FROM CatalogRevisionSources WHERE revision_id = NEW.revision_id)
	OR NOT EXISTS (SELECT 1 FROM CatalogRevisionTaxa WHERE revision_id = NEW.revision_id AND kind = 'product')
	OR NOT EXISTS (SELECT 1 FROM CatalogRevisionTaxa t JOIN CatalogRevisions r ON r.revision_id = t.revision_id
		WHERE t.revision_id = NEW.revision_id AND t.kind = 'family' AND t.slug = r.primary_family)
BEGIN SELECT RAISE(ABORT, 'Publication requires sources, products, and primary family association'); END;

CREATE TRIGGER catalog_revision_frozen_update BEFORE UPDATE ON CatalogRevisions
WHEN EXISTS (SELECT 1 FROM CatalogPublications WHERE revision_id IN (OLD.revision_id, NEW.revision_id))
BEGIN SELECT RAISE(ABORT, 'Published revisions are immutable'); END;
-- INSERT guards also reject SQLite REPLACE, whose implicit deletion need not fire
-- DELETE triggers when recursive_triggers is disabled.
CREATE TRIGGER catalog_revision_frozen_insert BEFORE INSERT ON CatalogRevisions
WHEN EXISTS (SELECT 1 FROM CatalogPublications WHERE revision_id = NEW.revision_id)
BEGIN SELECT RAISE(ABORT, 'Published revisions are immutable'); END;
CREATE TRIGGER catalog_revision_frozen_delete BEFORE DELETE ON CatalogRevisions
WHEN EXISTS (SELECT 1 FROM CatalogPublications WHERE revision_id = OLD.revision_id)
BEGIN SELECT RAISE(ABORT, 'Published revisions are immutable'); END;
CREATE TRIGGER catalog_publication_frozen_update BEFORE UPDATE ON CatalogPublications
BEGIN SELECT RAISE(ABORT, 'Publication history is immutable'); END;
CREATE TRIGGER catalog_publication_frozen_insert BEFORE INSERT ON CatalogPublications
WHEN EXISTS (SELECT 1 FROM CatalogPublications WHERE revision_id = NEW.revision_id)
BEGIN SELECT RAISE(ABORT, 'Publication history is immutable'); END;
CREATE TRIGGER catalog_publication_frozen_delete BEFORE DELETE ON CatalogPublications
BEGIN SELECT RAISE(ABORT, 'Publication history is immutable'); END;
CREATE TRIGGER catalog_taxa_frozen_insert BEFORE INSERT ON CatalogRevisionTaxa
WHEN EXISTS (SELECT 1 FROM CatalogPublications WHERE revision_id = NEW.revision_id)
BEGIN SELECT RAISE(ABORT, 'Published taxonomy is immutable'); END;
CREATE TRIGGER catalog_taxa_frozen_update BEFORE UPDATE ON CatalogRevisionTaxa
WHEN EXISTS (SELECT 1 FROM CatalogPublications WHERE revision_id IN (OLD.revision_id, NEW.revision_id))
BEGIN SELECT RAISE(ABORT, 'Published taxonomy is immutable'); END;
CREATE TRIGGER catalog_taxa_frozen_delete BEFORE DELETE ON CatalogRevisionTaxa
WHEN EXISTS (SELECT 1 FROM CatalogPublications WHERE revision_id = OLD.revision_id)
BEGIN SELECT RAISE(ABORT, 'Published taxonomy is immutable'); END;
CREATE TRIGGER catalog_sources_frozen_insert BEFORE INSERT ON CatalogRevisionSources
WHEN EXISTS (SELECT 1 FROM CatalogPublications WHERE revision_id = NEW.revision_id)
BEGIN SELECT RAISE(ABORT, 'Published sources are immutable'); END;
CREATE TRIGGER catalog_sources_frozen_update BEFORE UPDATE ON CatalogRevisionSources
WHEN EXISTS (SELECT 1 FROM CatalogPublications WHERE revision_id IN (OLD.revision_id, NEW.revision_id))
BEGIN SELECT RAISE(ABORT, 'Published sources are immutable'); END;
CREATE TRIGGER catalog_sources_frozen_delete BEFORE DELETE ON CatalogRevisionSources
WHEN EXISTS (SELECT 1 FROM CatalogPublications WHERE revision_id = OLD.revision_id)
BEGIN SELECT RAISE(ABORT, 'Published sources are immutable'); END;

-- Backfill identity only, not invented taxonomy, type, evidence, or review dates.
INSERT INTO CatalogEntries (practice_id, legacy_practice_id) SELECT practice_id, practice_id FROM BestPractices;
-- Share the numeric ID high-water mark without changing the old application's
-- INSERT/last_insert_rowid()/receipt transaction. Preserve previously deleted IDs.
UPDATE sqlite_sequence SET seq = MAX(seq, COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'BestPractices'), 0)) WHERE name = 'CatalogEntries';
INSERT INTO sqlite_sequence (name, seq)
SELECT 'CatalogEntries', COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'BestPractices'), 0)
WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'CatalogEntries');
CREATE TRIGGER catalog_reserve_legacy_sequence AFTER INSERT ON CatalogEntries
WHEN NEW.legacy_practice_id IS NULL
BEGIN
	UPDATE sqlite_sequence SET seq = MAX(seq, NEW.practice_id) WHERE name = 'BestPractices';
	INSERT INTO sqlite_sequence (name, seq) SELECT 'BestPractices', NEW.practice_id
	WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'BestPractices');
END;
CREATE TRIGGER catalog_legacy_identity BEFORE INSERT ON BestPractices
WHEN EXISTS (SELECT 1 FROM CatalogEntries WHERE practice_id = NEW.practice_id AND legacy_practice_id IS NULL)
BEGIN SELECT RAISE(ABORT, 'Catalog ID already reserved'); END;
CREATE TRIGGER catalog_legacy_created AFTER INSERT ON BestPractices
BEGIN INSERT INTO CatalogEntries (practice_id, legacy_practice_id) VALUES (NEW.practice_id, NEW.practice_id); END;

-- Summary-only view: no draft/body/source/receipt is read to serve a listing.
-- A legacy record is already published. Its single authority remains BestPractices;
-- it is not copied into a second independently editable body or fake revision.
CREATE VIEW PublishedCatalog AS
SELECT e.practice_id, NULL AS revision_id, 0 AS schema_version, 'legacy-practice' AS content_type,
	bp.title, substr(bp.description, 1, 500) AS summary, NULL AS primary_family,
	'unreviewed' AS evidence, 'unknown' AS maturity, bp.updated_at AS modified_at,
	NULL AS fact_verified_at, NULL AS review_due_at, 1 AS v1_eligible,
	'[]' AS families_json, '[]' AS products_json, '[]' AS outcomes_json
FROM CatalogEntries e JOIN BestPractices bp ON bp.practice_id = e.legacy_practice_id
WHERE e.published_revision_id IS NULL
UNION ALL
SELECT e.practice_id, r.revision_id, r.schema_version, r.content_type,
	r.title, r.summary, r.primary_family, r.evidence, r.maturity, r.modified_at,
	r.fact_verified_at, r.review_due_at, CASE WHEN e.legacy_practice_id IS NOT NULL THEN 1 ELSE 0 END,
	(SELECT json_group_array(slug) FROM (SELECT slug FROM CatalogRevisionTaxa WHERE revision_id = r.revision_id AND kind = 'family' ORDER BY slug)),
	(SELECT json_group_array(slug) FROM (SELECT slug FROM CatalogRevisionTaxa WHERE revision_id = r.revision_id AND kind = 'product' ORDER BY slug)),
	(SELECT json_group_array(slug) FROM (SELECT slug FROM CatalogRevisionTaxa WHERE revision_id = r.revision_id AND kind = 'outcome' ORDER BY slug))
FROM CatalogEntries e
JOIN CatalogPublications p ON p.practice_id = e.practice_id AND p.revision_id = e.published_revision_id
JOIN CatalogRevisions r ON r.practice_id = p.practice_id AND r.revision_id = p.revision_id;
PRAGMA optimize;
