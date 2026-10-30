#!/usr/bin/env python3
"""Credential-free upgrade/export self-tests. No production copy or remote access."""

import importlib.util
import json
import sqlite3
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from catalog_integrity import verify_catalog

spec = importlib.util.spec_from_file_location("public_export", ROOT / "scripts/export-public-catalog.py")
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


@contextmanager
def database(last=7):
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    for migration in sorted((ROOT / "migrations").glob("*.sql"))[:last]:
        db.executescript(migration.read_text())
    try:
        yield db
    finally:
        db.close()


def load_legacy_seed(db):
    # The checked-in seed can eventually contain native snapshots. An old-schema
    # upgrade must start from legacy public tables, not execute future-table SQL.
    with database() as current:
        current.executescript((ROOT / "initial_data.sql").read_text())
        sql = "\n".join(statement for table in ("Categories", "CloudflareFeatures", "BestPractices")
                        for statement in exporter.inserts(current, table))
    db.executescript(sql)


class CatalogModelTests(unittest.TestCase):
    def test_editorial_upgrade_keeps_frozen_native_snapshots_and_old_inserts(self):
        with database(6) as db:
            db.execute("INSERT INTO CatalogTaxa VALUES ('family', 'fixture', 'Fixture')")
            db.execute("INSERT INTO CatalogTaxa VALUES ('product', 'fixture', 'Fixture')")
            db.execute("INSERT INTO CatalogEntries (practice_id) VALUES (1000)")
            db.execute("""INSERT INTO CatalogRevisions (revision_id, practice_id, schema_version, content_type, title, summary, primary_family, applicability_json, body_json, evidence, maturity)
                VALUES (1, 1000, 1, 'recommendation', 'Frozen', 'Fixture', 'fixture', '{}', '{}', 'unreviewed', 'unknown')""")
            db.execute("INSERT INTO CatalogRevisionTaxa VALUES (1, 'family', 'fixture')")
            db.execute("INSERT INTO CatalogRevisionTaxa VALUES (1, 'product', 'fixture')")
            db.execute("INSERT INTO CatalogRevisionSources VALUES (1, 0, 'https://example.com/', 'Fixture')")
            db.execute("INSERT INTO CatalogPublications VALUES (1000, 1, '2026-10-30')")
            db.execute("UPDATE CatalogEntries SET published_revision_id = 1 WHERE practice_id = 1000")
            before = tuple(db.execute('SELECT * FROM CatalogRevisions').fetchone())
            db.executescript((ROOT / 'migrations/0007_editorial_workflow.sql').read_text())
            after = tuple(db.execute('SELECT * FROM CatalogRevisions').fetchone())
            self.assertEqual(before, after[:-1])
            self.assertEqual('active', json.loads(after[-1])['state'])
            with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable'):
                db.execute("UPDATE CatalogRevisions SET lifecycle_json = '{}' WHERE revision_id = 1")
            db.execute("INSERT INTO BestPractices (title, description, domain) VALUES ('Old app', 'Fixture', 'General')")
            self.assertEqual(1001, db.execute('SELECT last_insert_rowid()').fetchone()[0])

    def test_existing_seed_upgrade_retains_all_rows_and_receipts(self):
        with database(5) as db:
            load_legacy_seed(db)
            db.execute("INSERT INTO PracticeCreations VALUES ('private-key-fixture', 'private-hash-fixture', 1, '2026-01-01')")
            before = {table: [tuple(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY 1")] for table in ("BestPractices", "Categories", "CloudflareFeatures", "PracticeCreations")}
            db.executescript((ROOT / "migrations/0006_catalog_model.sql").read_text())
            db.executescript((ROOT / "migrations/0007_editorial_workflow.sql").read_text())
            for table, rows in before.items():
                self.assertEqual(rows, [tuple(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY 1")])
            self.assertEqual(len(before["BestPractices"]), db.execute("SELECT COUNT(*) FROM PublishedCatalog").fetchone()[0])
            verify_catalog(db, public_seed=False)

    def test_old_insert_allocator_and_rollback_remain_safe_after_native_reservations(self):
        with database() as db:
            db.execute("INSERT INTO CatalogEntries (practice_id) VALUES (1000)")
            db.execute("DELETE FROM CatalogEntries WHERE practice_id = 1000")
            # Same SQL shape used by the pre-upgrade app; trigger changes must not
            # change its last_insert_rowid() or allow a native-ID collision.
            db.execute("INSERT INTO BestPractices (title, description, domain) VALUES ('fixture', 'fixture', 'General')")
            self.assertEqual(1001, db.execute("SELECT last_insert_rowid()").fetchone()[0])
            self.assertEqual(1001, db.execute("SELECT legacy_practice_id FROM CatalogEntries").fetchone()[0])

    def test_backfill_keeps_deleted_legacy_id_high_water(self):
        with database(5) as db:
            db.execute("INSERT INTO BestPractices (practice_id, title, description, domain) VALUES (5000, 'fixture', 'fixture', 'General')")
            db.execute("DELETE FROM BestPractices WHERE practice_id = 5000")
            db.executescript((ROOT / "migrations/0006_catalog_model.sql").read_text())
            self.assertEqual(5001, db.execute("INSERT INTO CatalogEntries DEFAULT VALUES RETURNING practice_id").fetchone()[0])

    def test_public_export_round_trip_excludes_private_content(self):
        with database() as db, database() as clean:
            load_legacy_seed(db)
            db.executescript((ROOT / "data/catalog-taxonomy.sql").read_text())
            db.execute("INSERT INTO CatalogTaxa VALUES ('product', 'fixture', 'Fixture')")
            db.execute("INSERT INTO CatalogTaxa VALUES ('product', 'private-fixture', 'PRIVATE_TAXON')")
            for entry in (1000, 1001):
                db.execute("INSERT INTO CatalogEntries (practice_id) VALUES (?)", (entry,))
            body = json.dumps({"rationale": "fixture", "guidance": [{"kind": "prose", "text": "fixture"}], "validation": ["fixture"]})
            applicability = json.dumps({"requires": ["fixture"], "excludes": [], "dependencies": []})
            for revision, title in ((1, "Published fixture"), (2, "PRIVATE_REVISION")):
                db.execute("""INSERT INTO CatalogRevisions (revision_id, practice_id, schema_version, content_type, title, summary, primary_family, applicability_json, body_json, evidence, maturity)
                    VALUES (?, 1000, 1, 'recommendation', ?, 'fixture', 'application-services', ?, ?, 'unreviewed', 'unknown')""", (revision, title, applicability, body))
            db.execute("INSERT INTO CatalogRevisionTaxa VALUES (1, 'family', 'application-services')")
            db.execute("INSERT INTO CatalogRevisionTaxa VALUES (1, 'product', 'fixture')")
            db.execute("INSERT INTO CatalogRevisionTaxa VALUES (2, 'product', 'private-fixture')")
            db.execute("INSERT INTO CatalogRevisionSources VALUES (1, 0, 'https://example.com/', 'Public fixture')")
            db.execute("INSERT INTO CatalogRevisionSources VALUES (2, 0, 'https://example.com/private', 'PRIVATE_SOURCE')")
            db.execute("UPDATE CatalogRevisions SET lifecycle_json = ? WHERE revision_id = 1", (json.dumps({'state': 'deprecated', 'reason': 'Public retirement fixture.', 'supersededBy': None}),))
            db.execute("INSERT INTO CatalogPublications VALUES (1000, 1, '2026-10-30')")
            db.execute("UPDATE CatalogEntries SET published_revision_id = 1 WHERE practice_id = 1000")
            db.execute("INSERT INTO CatalogDrafts (practice_id, content_json) VALUES (1000, '{\"title\":\"PRIVATE_DRAFT\"}')")
            db.execute("INSERT INTO EditorialRoles VALUES (?, 'reviewer')", ('a' * 64,))
            db.execute("INSERT INTO EditorialAuthors VALUES (1000, 'PRIVATE_AUTHOR')")
            db.execute("INSERT INTO EditorialDraftState VALUES (1000, 'draft', 1, NULL)")
            db.execute("INSERT INTO EditorialMutations (operation_key, payload_hash, attempt, guard, practice_id, version, purge) VALUES ('PRIVATE_OPERATION', 'PRIVATE_HASH', 'PRIVATE_ATTEMPT', 1, 1000, 2, 0)")
            db.execute("INSERT INTO EditorialReviews (operation_key, practice_id, draft_version, reviewer_hash, decision) VALUES ('PRIVATE_OPERATION', 1000, 1, 'PRIVATE_REVIEWER', 'approve')")
            db.execute("INSERT INTO PracticeCreations VALUES ('PRIVATE_RECEIPT', 'PRIVATE_HASH', 1, '2026-01-01')")
            db.execute("ALTER TABLE BestPractices ADD COLUMN private_fixture TEXT")
            db.execute("UPDATE BestPractices SET private_fixture = 'PRIVATE_LEGACY_COLUMN'")
            db.execute("ALTER TABLE CatalogRevisions ADD COLUMN private_fixture TEXT DEFAULT 'PRIVATE_REVISION_COLUMN'")
            sql = exporter.public_sql(db)
            self.assertNotIn("PRIVATE_", sql)
            self.assertNotIn("private-fixture", sql)
            self.assertNotIn("CatalogDrafts", sql)
            self.assertNotIn("PracticeCreations", sql)
            self.assertNotIn("Editorial", sql)
            clean.executescript(sql)
            verify_catalog(clean)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM BestPractices").fetchone()[0] + 1,
                             clean.execute("SELECT COUNT(*) FROM PublishedCatalog").fetchone()[0])
            self.assertEqual([tuple(row) for row in db.execute("SELECT * FROM PublishedCatalog ORDER BY practice_id")], [tuple(row) for row in clean.execute("SELECT * FROM PublishedCatalog ORDER BY practice_id")])


if __name__ == "__main__":
    unittest.main()
