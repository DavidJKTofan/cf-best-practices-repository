-- Private role grants/working state/receipts must never enter public snapshots.
CREATE TABLE EditorialRoles (
	actor_hash TEXT NOT NULL CHECK (length(actor_hash) = 64),
	role TEXT NOT NULL CHECK (role IN ('editor', 'reviewer', 'publisher')),
	PRIMARY KEY (actor_hash, role)
);
ALTER TABLE CatalogDrafts ADD COLUMN lifecycle_json TEXT NOT NULL DEFAULT '{"state":"active","reason":null,"supersededBy":null}' CHECK (json_valid(lifecycle_json));
ALTER TABLE CatalogRevisions ADD COLUMN lifecycle_json TEXT NOT NULL DEFAULT '{"state":"active","reason":null,"supersededBy":null}' CHECK (json_valid(lifecycle_json));
CREATE TABLE EditorialDraftState (
	practice_id INTEGER PRIMARY KEY REFERENCES CatalogDrafts(practice_id),
	status TEXT NOT NULL CHECK (status IN ('draft', 'in-review', 'approved', 'published')),
	base_revision_id INTEGER,
	reviewer_hash TEXT,
	CHECK ((status IN ('approved', 'published')) = (reviewer_hash IS NOT NULL))
);
-- Conservatively retain all contributors: none may approve or publish this entry.
CREATE TABLE EditorialAuthors (
	practice_id INTEGER NOT NULL REFERENCES CatalogEntries(practice_id),
	actor_hash TEXT NOT NULL,
	PRIMARY KEY (practice_id, actor_hash)
);
CREATE TABLE EditorialMutations (
	operation_key TEXT PRIMARY KEY,
	payload_hash TEXT NOT NULL,
	attempt TEXT NOT NULL,
	-- A failed optimistic precondition aborts the entire D1 batch.
	guard INTEGER NOT NULL CHECK (guard = 1),
	practice_id INTEGER REFERENCES CatalogEntries(practice_id),
	version INTEGER NOT NULL,
	revision_id INTEGER,
	purge INTEGER NOT NULL CHECK (purge IN (0, 1)),
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE EditorialReviews (
	operation_key TEXT PRIMARY KEY REFERENCES EditorialMutations(operation_key),
	practice_id INTEGER NOT NULL REFERENCES CatalogEntries(practice_id),
	draft_version INTEGER NOT NULL,
	reviewer_hash TEXT NOT NULL,
	decision TEXT NOT NULL CHECK (decision IN ('approve', 'request-changes')),
	reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TRIGGER editorial_review_immutable_update BEFORE UPDATE ON EditorialReviews
BEGIN SELECT RAISE(ABORT, 'Review history is immutable'); END;
CREATE TRIGGER editorial_review_immutable_delete BEFORE DELETE ON EditorialReviews
BEGIN SELECT RAISE(ABORT, 'Review history is immutable'); END;
CREATE TRIGGER editorial_review_immutable_insert BEFORE INSERT ON EditorialReviews
WHEN EXISTS (SELECT 1 FROM EditorialReviews WHERE operation_key = NEW.operation_key)
BEGIN SELECT RAISE(ABORT, 'Review history is immutable'); END;
-- Add lifecycle data without changing the legacy/native publication boundary.
DROP VIEW PublishedCatalog;
CREATE VIEW PublishedCatalog AS
SELECT e.practice_id, NULL AS revision_id, 0 AS schema_version, 'legacy-practice' AS content_type,
	bp.title, substr(bp.description, 1, 500) AS summary, NULL AS primary_family,
	'unreviewed' AS evidence, 'unknown' AS maturity, bp.updated_at AS modified_at,
	NULL AS fact_verified_at, NULL AS review_due_at, 1 AS v1_eligible,
	'[]' AS families_json, '[]' AS products_json, '[]' AS outcomes_json,
	'{"state":"active","reason":null,"supersededBy":null}' AS lifecycle_json
FROM CatalogEntries e JOIN BestPractices bp ON bp.practice_id = e.legacy_practice_id
WHERE e.published_revision_id IS NULL
UNION ALL
SELECT e.practice_id, r.revision_id, r.schema_version, r.content_type,
	r.title, r.summary, r.primary_family, r.evidence, r.maturity, r.modified_at,
	r.fact_verified_at, r.review_due_at, CASE WHEN e.legacy_practice_id IS NOT NULL THEN 1 ELSE 0 END,
	(SELECT json_group_array(slug) FROM (SELECT slug FROM CatalogRevisionTaxa WHERE revision_id = r.revision_id AND kind = 'family' ORDER BY slug)),
	(SELECT json_group_array(slug) FROM (SELECT slug FROM CatalogRevisionTaxa WHERE revision_id = r.revision_id AND kind = 'product' ORDER BY slug)),
	(SELECT json_group_array(slug) FROM (SELECT slug FROM CatalogRevisionTaxa WHERE revision_id = r.revision_id AND kind = 'outcome' ORDER BY slug)),
	r.lifecycle_json
FROM CatalogEntries e
JOIN CatalogPublications p ON p.practice_id = e.practice_id AND p.revision_id = e.published_revision_id
JOIN CatalogRevisions r ON r.practice_id = p.practice_id AND r.revision_id = p.revision_id;
