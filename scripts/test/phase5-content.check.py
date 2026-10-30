#!/usr/bin/env python3
"""Disposable-only expansion/legacy/audit/export checks. No remote access."""

import importlib.util
import json
import re
import sqlite3
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from catalog_integrity import verify_catalog

verify_spec = importlib.util.spec_from_file_location("verify_content", ROOT / "scripts/verify-content.py")
verifier = importlib.util.module_from_spec(verify_spec)
verify_spec.loader.exec_module(verifier)
PATCHES, apply_twice, snapshot = verifier.PATCHES, verifier.apply_twice, verifier.snapshot

spec = importlib.util.spec_from_file_location("public_export", ROOT / "scripts/export-public-catalog.py")
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)
STARTERS = json.loads((ROOT / "data/phase5/starters.json").read_text())
SQL = (ROOT / "data/phase5/local-starters.sql").read_text()


@contextmanager
def database(seed=True):
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    for path in sorted((ROOT / "migrations").glob("*.sql")):
        db.executescript(path.read_text())
    if seed:
        db.executescript((ROOT / "initial_data.sql").read_text())
        for path in PATCHES:
            db.executescript((ROOT / path).read_text())
    try:
        yield db
    finally:
        db.close()


class Phase5Tests(unittest.TestCase):
    def test_audit_covers_each_existing_id_once_without_inventing_verification(self):
        audit = (ROOT / "docs/phase5/legacy-audit.md").read_text()
        rows = re.findall(r"^\|\s*(\d+)\s*\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|$", audit, re.M)
        with database() as db:
            ids = {row[0] for row in db.execute("SELECT practice_id FROM BestPractices")}
            self.assertEqual(119, len(rows))
            self.assertEqual(ids, {int(row[0]) for row in rows})
            self.assertEqual(len(ids), len(rows))
            for _, family, products, kind, reason in rows:
                self.assertIn(family.strip(), {"application-services", "cloudflare-one", "developer-platform", "network-services", "platform-operations"})
                self.assertIn(kind.strip(), {"recommendation", "rule-policy", "reference-architecture", "implementation-guide", "operational-runbook"})
                self.assertTrue(products.strip() and len(reason.strip()) > 30)

    def test_local_patch_twice_preserves_legacy_and_populates_only_two_starter_families(self):
        with database() as db:
            before = [tuple(row) for row in db.execute("SELECT * FROM BestPractices ORDER BY practice_id")]
            apply_twice(db, SQL, "Phase 5 disposable starters")
            verify_catalog(db)
            self.assertEqual(before, [tuple(row) for row in db.execute("SELECT * FROM BestPractices ORDER BY practice_id")])
            self.assertEqual([("cloudflare-one", 2), ("developer-platform", 2)], [tuple(row) for row in db.execute("SELECT primary_family, COUNT(*) FROM PublishedCatalog WHERE schema_version = 1 GROUP BY primary_family ORDER BY 1")])
            self.assertEqual(123, db.execute("SELECT COUNT(*) FROM PublishedCatalog").fetchone()[0])
            self.assertFalse(db.execute("SELECT lower(title) FROM PublishedCatalog GROUP BY lower(title) HAVING COUNT(*) > 1").fetchall())
            self.assertEqual(119, db.execute("SELECT COUNT(*) FROM PublishedCatalog WHERE v1_eligible = 1").fetchone()[0])
            self.assertEqual(0, db.execute("SELECT COUNT(*) FROM EditorialReviews").fetchone()[0])

    def test_collisions_and_deleted_id_high_water_fail_before_any_snapshot_write(self):
        for setup in (
            "INSERT INTO CatalogEntries (practice_id) VALUES (810001)",
            "INSERT INTO CatalogEntries (practice_id) VALUES (810010); DELETE FROM CatalogEntries WHERE practice_id = 810010",
        ):
            with self.subTest(setup=setup), database() as db:
                db.executescript(setup)
                before = snapshot(db)
                with self.assertRaises(sqlite3.IntegrityError):
                    db.executescript(SQL)
                self.assertEqual(before, snapshot(db))

    def test_altered_published_snapshot_is_not_replaced_by_local_reseed(self):
        with database() as db:
            db.executescript(SQL)
            # Unselected working revision: the local snapshot must never select it.
            db.execute("INSERT INTO CatalogRevisions (practice_id, schema_version, content_type, title, summary, primary_family, applicability_json, body_json, evidence, maturity) VALUES (810001, 1, 'recommendation', 'Private', 'Private', 'cloudflare-one', '{}', '{}', 'unreviewed', 'unknown')")
            apply_twice(db, SQL, "Phase 5 with private revision")
            self.assertEqual(810001, db.execute("SELECT published_revision_id FROM CatalogEntries WHERE practice_id = 810001").fetchone()[0])
            # A source/metadata collision must fail closed, not silently pass an old patch.
            db.execute("DROP TRIGGER catalog_sources_frozen_update")
            db.execute("UPDATE CatalogRevisionSources SET title = 'Changed snapshot' WHERE revision_id = 810001 AND position = 0")
            db.commit()
            before = snapshot(db)
            with self.assertRaises(sqlite3.IntegrityError):
                db.executescript(SQL)
            self.assertEqual(before, snapshot(db))

    def test_public_snapshot_round_trip_preserves_all_four_typed_variants(self):
        with database() as db, database(seed=False) as clean:
            db.executescript(SQL)
            clean.executescript(exporter.public_sql(db))
            verify_catalog(clean)
            self.assertEqual([tuple(row) for row in db.execute("SELECT * FROM PublishedCatalog ORDER BY practice_id")], [tuple(row) for row in clean.execute("SELECT * FROM PublishedCatalog ORDER BY practice_id")])
            self.assertEqual(2, clean.execute("SELECT COUNT(*) FROM CatalogRevisions WHERE json_extract(body_json, '$.variant') = 'operational-runbook'").fetchone()[0])
            self.assertEqual(119, clean.execute("SELECT COUNT(*) FROM BestPractices").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
