#!/usr/bin/env python3
"""Synthetic-only release tooling checks, never a production-copy rehearsal."""

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import release_rehearsal as release


def fixture(baseline):
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    for migration in release.MIGRATIONS[:baseline]:
        db.executescript(migration.read_text())
    db.executescript((ROOT / "initial_data.sql").read_text())
    db.execute("INSERT INTO PracticeCreations VALUES ('PRIVATE_RECEIPT', 'PRIVATE_HASH', 18, '2026-01-01')")
    # A deleted high ID and unrelated private state must survive, too.
    db.execute("UPDATE sqlite_sequence SET seq = 9000 WHERE name = 'BestPractices'")
    db.executescript("CREATE TABLE PrivateRecovery (id INTEGER PRIMARY KEY AUTOINCREMENT, secret TEXT);"
                     "INSERT INTO PrivateRecovery VALUES (42, 'PRIVATE_RECOVERY'); DELETE FROM PrivateRecovery;")
    if baseline >= 6:
        db.executescript((ROOT / "data/catalog-taxonomy.sql").read_text())
        db.executescript((ROOT / "data/phase5-products.sql").read_text())
        # Test-only snapshots, including an already published runbook, exercise
        # upgrade/recovery. The rehearsal tool itself NEVER loads these files.
        for index, starter in enumerate(json.loads((ROOT / "data/phase5/starters.json").read_text())):
            entry = starter['content']
            practice_id = 810001 + index
            db.execute("INSERT INTO CatalogEntries (practice_id) VALUES (?)", (practice_id,))
            revision_id = db.execute("""INSERT INTO CatalogRevisions
                (practice_id, schema_version, content_type, title, summary, primary_family, applicability_json, body_json, evidence, maturity, modified_at, fact_verified_at, review_due_at)
                VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING revision_id""",
                (practice_id, entry['type'], entry['title'], entry['summary'], entry['primaryFamily'], json.dumps(entry['applicability']),
                 json.dumps(entry['body']), entry['evidence'], entry['maturity'], entry['modifiedAt'], entry['factVerifiedAt'], entry['reviewDueAt'])).fetchone()[0]
            for kind, field in (("family", "families"), ("product", "products"), ("outcome", "outcomes")):
                for slug in entry[field]:
                    db.execute("INSERT INTO CatalogRevisionTaxa VALUES (?, ?, ?)", (revision_id, kind, slug))
            for position, source in enumerate(entry['sources']):
                db.execute("INSERT INTO CatalogRevisionSources VALUES (?, ?, ?, ?)", (revision_id, position, source['url'], source['title']))
            db.execute("INSERT INTO CatalogPublications VALUES (?, ?, '2026-10-30')", (practice_id, revision_id))
            db.execute("UPDATE CatalogEntries SET published_revision_id = ? WHERE practice_id = ?", (revision_id, practice_id))
        db.execute("INSERT INTO CatalogEntries (practice_id) VALUES (900001)")
        db.execute("DELETE FROM CatalogEntries WHERE practice_id = 900001")
        db.execute("INSERT INTO CatalogDrafts (practice_id, content_json) VALUES (810001, '{\"secret\":\"PRIVATE_DRAFT\"}')")
    if baseline >= 7:
        db.execute("INSERT INTO EditorialRoles VALUES (?, 'reviewer')", ('a' * 64,))
        db.execute("INSERT INTO EditorialAuthors VALUES (810001, 'PRIVATE_AUTHOR')")
        db.execute("INSERT INTO EditorialDraftState VALUES (810001, 'draft', 1, NULL)")
        db.execute("INSERT INTO EditorialMutations (operation_key, payload_hash, attempt, guard, practice_id, version, purge) VALUES ('PRIVATE_KEY', 'PRIVATE_HASH', 'PRIVATE_ATTEMPT', 1, 810001, 1, 0)")
        db.execute("INSERT INTO EditorialReviews (operation_key, practice_id, draft_version, reviewer_hash, decision) VALUES ('PRIVATE_KEY', 810001, 1, 'PRIVATE_REVIEWER', 'request-changes')")
    db.commit()
    return db


def sequences(db):
    loaded = dict(db.execute("SELECT name, seq FROM sqlite_sequence"))
    return {row[0]: loaded.get(row[0], 0) for row in db.execute(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND upper(sql) LIKE '%AUTOINCREMENT%'")}


class ReleaseRehearsalTests(unittest.TestCase):
    def test_optimizer_statistics_are_derived_but_private_application_data_is_preserved(self):
        with closing(fixture(5)) as db:
            db.execute("CREATE TABLE PrivateStatistics (value TEXT)")
            db.execute("INSERT INTO PrivateStatistics VALUES ('private canary')")
            db.execute("ANALYZE")
            self.assertIn("sqlite_stat1", release.tables(db))
            before = release.capture(db)
            self.assertFalse("sqlite_stat1" in before)
            self.assertFalse("sqlite_stat4" in before)
            self.assertIn("PrivateStatistics", before)
            release.rehearse(db, 5, sequences(db))
            release.unchanged(db, before)
            db.execute("UPDATE PrivateStatistics SET value = 'changed'")
            with self.assertRaisesRegex(AssertionError, "Existing table data changed"):
                release.unchanged(db, before)

    def test_all_baselines_preserve_private_state_and_do_not_contaminate_with_probes(self):
        for baseline in release.BASELINES:
            with self.subTest(baseline=baseline), closing(fixture(baseline)) as db:
                before = release.capture(db)
                floor = sequences(db)
                result = release.rehearse(db, baseline, floor)
                self.assertEqual("offline-sqlite-only", result["scope"])
                self.assertEqual("none", result["remoteEffects"])
                self.assertEqual(list(release.content.PATCHES), result["patchesRehearsedTwice"])
                self.assertNotIn("local-starters.sql", json.dumps(result))
                self.assertEqual(before["PracticeCreations"][1], release.rows(db, "PracticeCreations"))
                self.assertFalse(db.execute("SELECT 1 FROM BestPractices WHERE title = 'Phase 6 SQL probe'").fetchone())
                release.verify_sequence_floor(db, floor)
                if baseline >= 7:
                    for table in before:
                        if table.startswith("Editorial"):
                            self.assertEqual(before[table][1], release.rows(db, table))

    def test_requires_complete_separate_allocator_capture_and_rejects_regression(self):
        for mutation in (lambda x: {}, lambda x: {**x, "BestPractices": 1}, lambda x: {**x, "unknown": 10},
                         lambda x: {**x, "BestPractices": True}, lambda x: {k: v for k, v in x.items() if k != "PrivateRecovery"}):
            with closing(fixture(5)) as db:
                with self.assertRaises(AssertionError):
                    release.rehearse(db, 5, mutation(sequences(db)))

    def test_restores_deleted_id_floor_missing_from_sql_dump(self):
        with closing(fixture(5)) as db:
            captured = sequences(db)
            db.execute("UPDATE sqlite_sequence SET seq = 120 WHERE name = 'BestPractices'")
            release.rehearse(db, 5, captured)
            self.assertEqual(9000, sequences(db)["CatalogEntries"])

    def test_rejects_wrong_partial_and_newer_baselines_or_ledgers(self):
        with closing(fixture(5)) as db:
            for baseline in (6, 7):
                with self.assertRaises(AssertionError):
                    release.validate_baseline(db, baseline)
            db.execute("CREATE TABLE CatalogEntries (practice_id INTEGER)")
            with self.assertRaises(AssertionError):
                release.validate_baseline(db, 5)
        with closing(fixture(5)) as db:
            db.execute("CREATE TABLE d1_migrations (name TEXT)")
            for name in ("9999_unknown.sql", release.MIGRATIONS[5].name):
                db.execute("DELETE FROM d1_migrations")
                db.execute("INSERT INTO d1_migrations VALUES (?)", (name,))
                with self.assertRaises(AssertionError):
                    release.validate_baseline(db, 5)

    def test_catches_foreign_key_damage_and_export_filesystem_escape(self):
        with closing(sqlite3.connect(":memory:")) as db:
            for sql in ("ATTACH DATABASE '/not-allowed' AS other;", "PRAGMA writable_schema = ON;",
                        "SELECT load_extension('not-allowed');", "SELECT writefile('not-allowed', 'x');"):
                with self.assertRaises(sqlite3.DatabaseError):
                    release.import_sql(db, sql)
        with closing(fixture(5)) as db:
            db.execute("UPDATE PracticeCreations SET practice_id = -1")
            with self.assertRaises(AssertionError):
                release.integrity(db)

    def test_does_not_certify_exports_missing_or_replacing_publication_guards(self):
        with closing(fixture(7)) as db:
            db.execute("DROP TRIGGER catalog_revision_frozen_update")
            with self.assertRaisesRegex(AssertionError, "Missing baseline"):
                release.validate_baseline(db, 7)
        with closing(fixture(7)) as db:
            db.execute("DROP VIEW PublishedCatalog")
            db.execute("CREATE VIEW PublishedCatalog AS SELECT * FROM CatalogRevisions")
            with self.assertRaisesRegex(AssertionError, "trigger/view differs"):
                release.validate_baseline(db, 7)

    def test_cli_inputs_are_read_only_outputs_exclusive_private_and_reports_redacted(self):
        with tempfile.TemporaryDirectory() as temp, closing(fixture(7)) as db:
            temp = Path(temp)
            source, seq = temp / "full.sql", temp / "sequences.json"
            source.write_text(release.content.snapshot(db))
            seq.write_text(json.dumps(sequences(db)))
            original = source.read_bytes()
            output = temp / "new-copy"
            result = release.run(source, seq, 7, output)
            self.assertEqual(original, source.read_bytes())
            self.assertNotIn("PRIVATE_", json.dumps(result))
            self.assertNotIn(str(temp), json.dumps(result))
            if os.name == "posix":
                for path, mode in ((output, 0o700), (output / "rehearsal.sqlite", 0o600), (output / "result.json", 0o600), (output / "provenance.json", 0o600)):
                    self.assertEqual(mode, path.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                release.run(source, seq, 7, output)
            alias = temp / "alias"
            alias.symlink_to(output, target_is_directory=True)
            with self.assertRaises(FileExistsError):
                release.run(source, seq, 7, alias)
            with self.assertRaises(AssertionError):
                release.run(ROOT / "initial_data.sql", seq, 7, temp / "refused")
            with self.assertRaises(AssertionError):
                release.run(source, seq, 7, ROOT / "refused-release-copy")

    def test_failed_copy_is_retained_with_private_not_public_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            source, seq, output = temp / "bad.sql", temp / "sequences.json", temp / "failed"
            source.write_text("SELECT 'PRIVATE_FIXTURE' FROM missing_private_table;")
            seq.write_text('{}')
            with self.assertRaises(RuntimeError) as error:
                release.run(source, seq, 5, output)
            self.assertNotIn('missing_private_table', str(error.exception))
            self.assertTrue((output / "rehearsal.sqlite").is_file())
            self.assertFalse((output / "result.json").exists())
            self.assertIn('missing_private_table', (output / "failure.txt").read_text())


if __name__ == "__main__":
    unittest.main()
