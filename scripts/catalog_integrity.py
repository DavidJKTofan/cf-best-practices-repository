"""Offline relational/seed checks, not a replacement for the TypeScript body validator."""

import json


def verify_catalog(db, public_seed=True):
    def require(condition, message):
        if not condition:
            raise AssertionError(message)

    require(not db.execute("PRAGMA foreign_key_check").fetchall(), "Catalog foreign-key violations")
    require(not db.execute("""SELECT bp.practice_id FROM BestPractices bp LEFT JOIN CatalogEntries e
        ON e.legacy_practice_id = bp.practice_id WHERE e.practice_id IS NULL""").fetchall(), "Missing legacy identity backfill")
    require(not db.execute("""SELECT * FROM PublishedCatalog WHERE schema_version = 0 AND
        (revision_id IS NOT NULL OR primary_family IS NOT NULL OR evidence != 'unreviewed'
         OR maturity != 'unknown' OR fact_verified_at IS NOT NULL)""").fetchall(), "Invented legacy classification/verification")
    for row in db.execute("SELECT * FROM CatalogRevisions WHERE revision_id IN (SELECT published_revision_id FROM CatalogEntries)"):
        body = json.loads(row["body_json"])
        require(isinstance(body, dict), "Published body is not an object")
        require(len(row["body_json"].encode()) <= 65536, "Oversize published body")
        require(isinstance(json.loads(row["applicability_json"]), dict), "Invalid applicability")
        require((row["evidence"] == "unreviewed") == (row["fact_verified_at"] is None), "Evidence/date mismatch")
        require(db.execute("SELECT 1 FROM CatalogRevisionTaxa WHERE revision_id = ? AND kind = 'family' AND slug = ?", (row["revision_id"], row["primary_family"])).fetchone(), "Missing primary family association")
        require(db.execute("SELECT 1 FROM CatalogRevisionSources WHERE revision_id = ?", (row["revision_id"],)).fetchone(), "Missing published source")
    if public_seed:
        for table in ("PracticeCreations", "CatalogDrafts", "EditorialRoles", "EditorialDraftState", "EditorialAuthors", "EditorialMutations", "EditorialReviews"):
            require(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, f"Private {table} leaked into seed")
        require(not db.execute("SELECT revision_id FROM CatalogRevisions EXCEPT SELECT published_revision_id FROM CatalogEntries").fetchall(), "Unpublished/old revision leaked into seed")
        require(not db.execute("SELECT practice_id FROM CatalogEntries WHERE legacy_practice_id IS NULL AND published_revision_id IS NULL").fetchall(), "Draft-only identity leaked into seed")
