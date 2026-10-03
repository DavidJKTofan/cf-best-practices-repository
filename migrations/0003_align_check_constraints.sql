-- Migration number: 0003 	 Align CHECK constraints with 0001
--
-- The production tables predate 0001, so its CREATE TABLE IF NOT EXISTS statements never applied there and two
-- CHECK constraints drifted:
--   CloudflareFeatures.subscription_level  did not allow 'Paid Add-On'
--   BestPractices.difficulty_level         used IN (..., NULL), which accepts any value
-- SQLite cannot alter a CHECK constraint, so both tables are rebuilt with the 0001 definitions, keeping all rows and
-- IDs. On databases created from 0001 this is a harmless no-op rebuild.
--
-- Order matters: dropping a parent table that still has child rows leaves deferred foreign key violations that a
-- later RENAME does not clear. So the new child references the new parent, the old child is dropped before the old
-- parent, and RENAME then rewrites the child's foreign key to the final table name.

PRAGMA defer_foreign_keys = true;

-- 1. New parent table, with the corrected CHECK
CREATE TABLE CloudflareFeatures_new (
	feature_id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	feature_url TEXT,
	subscription_level TEXT CHECK (subscription_level IN ('Free', 'Pro', 'Business', 'Enterprise', 'Paid Add-On'))
);
INSERT INTO CloudflareFeatures_new (feature_id, name, feature_url, subscription_level)
SELECT feature_id, name, feature_url, subscription_level FROM CloudflareFeatures;

-- 2. New child table, referencing the new parent
CREATE TABLE BestPractices_new (
	practice_id INTEGER PRIMARY KEY AUTOINCREMENT,
	title TEXT NOT NULL,
	description TEXT NOT NULL,
	domain TEXT NOT NULL CHECK (domain IN ('Security', 'Performance', 'Reliability', 'General')),
	category_id INTEGER,
	feature_id INTEGER,
	recommendation_level TEXT CHECK (recommendation_level IN ('Mandatory', 'Recommended', 'Optional', 'Situational')),
	impact_level TEXT CHECK (impact_level IN ('High', 'Medium', 'Low')),
	difficulty_level TEXT CHECK (difficulty_level IS NULL OR difficulty_level IN ('Easy', 'Medium', 'Complex')),
	prerequisites TEXT,
	expressions_configuration_details TEXT,
	source_reference TEXT,
	notes TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (category_id) REFERENCES Categories (category_id),
	FOREIGN KEY (feature_id) REFERENCES CloudflareFeatures_new (feature_id)
);
INSERT INTO BestPractices_new (
	practice_id, title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level,
	prerequisites, expressions_configuration_details, source_reference, notes, created_at, updated_at
)
SELECT
	practice_id, title, description, domain, category_id, feature_id, recommendation_level, impact_level, difficulty_level,
	prerequisites, expressions_configuration_details, source_reference, notes, created_at, updated_at
FROM BestPractices;

-- 3. Drop the old child, then the old parent (nothing references it anymore)
DROP TABLE BestPractices;
DROP TABLE CloudflareFeatures;

-- 4. Rename; renaming the parent also rewrites BestPractices_new's foreign key to CloudflareFeatures
ALTER TABLE CloudflareFeatures_new RENAME TO CloudflareFeatures;
ALTER TABLE BestPractices_new RENAME TO BestPractices;

CREATE INDEX IF NOT EXISTS idx_bestpractices_category ON BestPractices (category_id);
CREATE INDEX IF NOT EXISTS idx_bestpractices_feature ON BestPractices (feature_id);
CREATE INDEX IF NOT EXISTS idx_bestpractices_domain ON BestPractices (domain);
CREATE INDEX IF NOT EXISTS idx_bestpractices_impact ON BestPractices (impact_level);
