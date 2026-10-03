-- Migration number: 0001 	 Initial schema
--
-- Idempotent (IF NOT EXISTS) so it can be applied to the existing production
-- database, where it is a no-op that simply records the baseline in d1_migrations.
--
-- Note: `difficulty_level` previously used CHECK(difficulty_level IN (..., NULL)).
-- In SQLite, `x IN (..., NULL)` evaluates to NULL for any x not in the list, and a
-- NULL CHECK result passes, so any value was accepted. The constraint below is the
-- corrected form; it only applies to newly created databases.

CREATE TABLE IF NOT EXISTS Categories (
	category_id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	description TEXT,
	display_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS CloudflareFeatures (
	feature_id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	feature_url TEXT,
	subscription_level TEXT CHECK (subscription_level IN ('Free', 'Pro', 'Business', 'Enterprise', 'Paid Add-On'))
);

CREATE TABLE IF NOT EXISTS BestPractices (
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
	FOREIGN KEY (feature_id) REFERENCES CloudflareFeatures (feature_id)
);

-- Foreign-key and filter columns (https://developers.cloudflare.com/d1/best-practices/use-indexes/)
CREATE INDEX IF NOT EXISTS idx_bestpractices_category ON BestPractices (category_id);
CREATE INDEX IF NOT EXISTS idx_bestpractices_feature ON BestPractices (feature_id);
CREATE INDEX IF NOT EXISTS idx_bestpractices_domain ON BestPractices (domain);
CREATE INDEX IF NOT EXISTS idx_bestpractices_impact ON BestPractices (impact_level);
