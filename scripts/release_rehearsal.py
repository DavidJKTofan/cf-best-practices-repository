"""Offline private-copy rehearsal. No Cloudflare client, subprocess, or network access.

This verifies SQLite/data compatibility, not workerd, Access, or edge-cache effects.
Only an owner-approved full export and separately captured allocator state qualify
as production-copy input. Tests deliberately use synthetic exports instead.
"""

import importlib.util
import hashlib
import json
import os
import re
import sqlite3
from contextlib import closing
from pathlib import Path

from catalog_integrity import verify_catalog

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = tuple(sorted((ROOT / "migrations").glob("*.sql")))
BASELINES = (5, 6, 7)


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


content = load_script("release_content", "verify-content.py")
exporter = load_script("release_export", "export-public-catalog.py")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def tables(db):
    return [row[0] for row in db.execute("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")]


def rows(db, table, columns=None):
    fields = ", ".join(map(quote, columns)) if columns else "*"
    # Sort values outside SQL: tables may have composite/no keys or mixed types.
    return sorted((tuple(row) for row in db.execute(f"SELECT {fields} FROM {quote(table)}")), key=repr)


def capture(db):
    # PRAGMA optimize/ANALYZE legitimately regenerate derived query-planner
    # statistics. Preserve all application/private tables; allocator floors are
    # checked separately. Do not broadly ignore unknown or private tables.
    return {name: ([row[1] for row in db.execute(f"PRAGMA table_info({quote(name)})")], rows(db, name))
            for name in tables(db) if name not in ("sqlite_sequence", "sqlite_stat1", "sqlite_stat4")}


def unchanged(db, before, except_tables=()):
    for table, (columns, values) in before.items():
        if table not in except_tables:
            require(rows(db, table, columns) == values, "Existing table data changed unexpectedly")


def integrity(db):
    require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "SQLite integrity check failed")
    require(not db.execute("PRAGMA foreign_key_check").fetchall(), "Foreign-key violations")


def import_authorizer(action, first, second, _database, _trigger):
    # SQL exports are approved input, but must not be able to read/write other
    # files via ATTACH, extension functions, or directory/schema PRAGMAs.
    denied = action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH)
    denied |= action == sqlite3.SQLITE_FUNCTION and (second or "").lower() in (
        "load_extension", "readfile", "writefile")
    denied |= action == sqlite3.SQLITE_PRAGMA and (first or "").lower() in (
        "writable_schema", "temp_store_directory", "data_store_directory")
    return sqlite3.SQLITE_DENY if denied else sqlite3.SQLITE_OK


def import_sql(db, sql):
    db.set_authorizer(import_authorizer)
    try:
        db.executescript(sql)
    finally:
        db.set_authorizer(None)
    db.commit()
    db.execute("PRAGMA foreign_keys = ON")
    integrity(db)


def validate_baseline(db, baseline):
    require(baseline in BASELINES, "Unsupported schema baseline")
    with closing(sqlite3.connect(":memory:")) as expected:
        for migration in MIGRATIONS[:baseline]:
            expected.executescript(migration.read_text())
        for table in tables(expected):
            if table == "sqlite_sequence":
                continue
            actual = {row[1] for row in db.execute(f"PRAGMA table_info({quote(table)})")}
            required = {row[1] for row in expected.execute(f"PRAGMA table_info({quote(table)})")}
            require(required <= actual, "Export is incomplete or does not match the declared baseline")
        actual_objects = {(row[0], row[1]): row[2] for row in db.execute(
            "SELECT type, name, sql FROM sqlite_schema WHERE type IN ('index', 'trigger', 'view') AND sql IS NOT NULL")}
        for kind, name, sql in expected.execute(
                "SELECT type, name, sql FROM sqlite_schema WHERE type IN ('index', 'trigger', 'view') AND sql IS NOT NULL"):
            require((kind, name) in actual_objects, "Missing baseline index, trigger, or published view")
            if kind in ("trigger", "view"):
                normalize = lambda value: re.sub(r"\s+", " ", value).strip().rstrip(";")
                require(normalize(sql) == normalize(actual_objects[(kind, name)]), "Baseline trigger/view differs; independent schema review required")
    names = set(tables(db))
    require(("CatalogEntries" in names) == (baseline >= 6), "Catalog baseline mismatch")
    require(("EditorialRoles" in names) == (baseline >= 7), "Editorial baseline mismatch")
    # Do not silently replay migrations against a partial/newer/contradictory DB.
    if "d1_migrations" in names:
        ledger = {row[0] for row in db.execute("SELECT name FROM d1_migrations")}
        known = {path.name for path in MIGRATIONS}
        require(ledger <= known, "Unknown migration ledger entry; review the export")
        require(not (ledger & {path.name for path in MIGRATIONS[baseline:]}), "Migration ledger contradicts baseline")
    # A public snapshot is not a full recovery copy, even if it has current tables.
    require(db.execute("SELECT COUNT(*) FROM BestPractices").fetchone()[0] > 0, "Empty catalog copy")


def restore_sequences(db, captured):
    require(isinstance(captured, dict) and captured, "Capture private sqlite_sequence state separately")
    automatic = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND upper(sql) LIKE '%AUTOINCREMENT%'")}
    require(set(captured) == automatic, "Sequence capture must cover every AUTOINCREMENT table (zero if unused)")
    loaded_rows = list(db.execute("SELECT name, seq FROM sqlite_sequence"))
    loaded = dict(loaded_rows)
    require(len(loaded) == len(loaded_rows), "Ambiguous duplicate allocator state")
    require(set(loaded) <= automatic, "Unexpected allocator state")
    for table, sequence in captured.items():
        require(type(sequence) is int and 0 <= sequence <= 9223372036854775807, "Invalid captured allocator")
        primary = [row[1] for row in db.execute(f"PRAGMA table_info({quote(table)})") if row[5]]
        require(len(primary) == 1, "Unexpected AUTOINCREMENT primary key")
        high = db.execute(f"SELECT COALESCE(MAX({quote(primary[0])}), 0) FROM {quote(table)}").fetchone()[0]
        require(sequence >= max(high, loaded.get(table, 0)), "Sequence capture is older than the export")
        db.execute("DELETE FROM sqlite_sequence WHERE name = ?", (table,))
        db.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", (table, sequence))
    db.commit()


def verify_sequence_floor(db, before):
    after = dict(db.execute("SELECT name, seq FROM sqlite_sequence"))
    require(all(after.get(name, -1) >= seq for name, seq in before.items()), "Allocator moved backwards")


def rollback_sql_probe(db):
    """Old-app SQL contract only. A running old Worker is a separate release gate."""
    with closing(sqlite3.connect(":memory:")) as probe:
        db.backup(probe)
        probe.execute("PRAGMA foreign_keys = ON")
        high = max(dict(probe.execute("SELECT name, seq FROM sqlite_sequence")).get(name, 0)
                   for name in ("BestPractices", "CatalogEntries"))
        require(high < 2147483645, "Insufficient ID headroom for rehearsal")
        native = probe.execute("INSERT INTO CatalogEntries DEFAULT VALUES RETURNING practice_id").fetchone()[0]
        probe.execute("DELETE FROM CatalogEntries WHERE practice_id = ?", (native,))
        probe.commit()
        before = capture(probe)
        key, payload = "phase6-synthetic-operation", "phase6-synthetic-payload"
        require(not probe.execute("SELECT 1 FROM PracticeCreations WHERE operation_key = ?", (key,)).fetchone(), "Probe identity collision")

        def create():
            with probe:
                probe.execute("""INSERT INTO BestPractices (title, description, domain)
                    SELECT 'Phase 6 SQL probe', 'Disposable probe', 'General'
                    WHERE NOT EXISTS (SELECT 1 FROM PracticeCreations WHERE operation_key = ?)""", (key,))
                probe.execute("""INSERT INTO PracticeCreations (operation_key, payload_hash, practice_id)
                    SELECT ?, ?, last_insert_rowid()
                    WHERE NOT EXISTS (SELECT 1 FROM PracticeCreations WHERE operation_key = ?)""", (key, payload, key))
            return tuple(probe.execute("SELECT practice_id, payload_hash FROM PracticeCreations WHERE operation_key = ?", (key,)).fetchone())

        first = create()
        require(first[0] > native > high, "Old insert reused a native/deleted reservation")
        after = capture(probe)
        require(create() == first and capture(probe) == after, "Old-app SQL replay changed durable state")
        unchanged(probe, before, ("BestPractices", "CatalogEntries", "PracticeCreations"))
        # Existing real receipts must remain byte-for-byte, not merely same count.
        require(set(before["PracticeCreations"][1]) <= set(rows(probe, "PracticeCreations")), "Receipt loss")
        snapshot = content.snapshot(probe)
        try:
            with probe:
                probe.execute("INSERT INTO BestPractices (title, description, domain) VALUES ('Rollback', 'Probe', 'General')")
                probe.execute("INSERT INTO PracticeCreations VALUES (?, ?, -1, CURRENT_TIMESTAMP)", (key + "-failure", payload))
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("Probe failed to force transaction rollback")
        require(content.snapshot(probe) == snapshot, "Failed batch left data, receipt, or allocator effects")
        integrity(probe)


def rehearse(db, baseline, sequences):
    validate_baseline(db, baseline)
    restore_sequences(db, sequences)
    before = capture(db)
    floor = dict(db.execute("SELECT name, seq FROM sqlite_sequence"))
    for migration in MIGRATIONS[baseline:]:
        db.executescript(migration.read_text())
        integrity(db)
        unchanged(db, before)
        verify_sequence_floor(db, floor)
    verify_catalog(db, public_seed=False)
    before_patches = capture(db)
    for name in content.PATCHES:
        content.apply_twice(db, (ROOT / name).read_text(), name)
        integrity(db)
    unchanged(db, before_patches, ("BestPractices", "Categories", "CloudflareFeatures", "CatalogTaxa", "CatalogTaxonAliases"))
    require({row[0] for row in before_patches["BestPractices"][1]} <= {row[0] for row in rows(db, "BestPractices")}, "Patch removed a legacy ID")
    verify_sequence_floor(db, floor)
    verify_catalog(db, public_seed=False)
    db.commit()
    rollback_sql_probe(db)
    # Full recovery, including private state and deleted-ID high-water marks.
    with closing(sqlite3.connect(":memory:")) as recovered:
        db.backup(recovered)
        require(content.snapshot(recovered) == content.snapshot(db), "Full private recovery differs")
        rollback_sql_probe(recovered)
    # Sanitized output is verified in memory only. Never refresh the seed here.
    with closing(sqlite3.connect(":memory:")) as public:
        public.row_factory = sqlite3.Row
        public.execute("PRAGMA foreign_keys = ON")
        for migration in MIGRATIONS:
            public.executescript(migration.read_text())
        public.executescript(exporter.public_sql(db))
        verify_catalog(public)
        require(rows(public, "PublishedCatalog") == rows(db, "PublishedCatalog"), "Public snapshot parity failure")
    return {
        "formatVersion": 1,
        "scope": "offline-sqlite-only",
        "baseline": baseline,
        "migrationsRehearsed": [path.name for path in MIGRATIONS[baseline:]],
        "patchesRehearsedTwice": list(content.PATCHES),
        "checks": ["existing-data-preserved", "allocator-floor", "old-write-sql-replay-rollback", "private-backup-recovery", "public-export-parity"],
        "notVerified": ["input-freshness-and-approval", "workerd-private-copy-import", "old-worker-runtime", "variant-reader-rollback", "live-cache-and-purge", "live-access", "browser-accessibility"],
        "remoteEffects": "none",
    }


def private_path(path, exists=False):
    resolved = Path(path).expanduser().resolve(strict=exists)
    require(not resolved.is_relative_to(ROOT), "Private rehearsal material must remain outside the repository")
    return resolved


def run(source, sequence_file, baseline, output):
    source, sequence_file = private_path(source, True), private_path(sequence_file, True)
    output = private_path(output)
    require(source.is_file() and sequence_file.is_file(), "Expected private input files")
    # Exclusive creation: never overwrite an export, previous rehearsal, ordinary
    # local D1 state, or a symlink to one. Keep failed partial effects for diagnosis.
    output.mkdir(mode=0o700)
    os.chmod(output, 0o700)
    database = output / "rehearsal.sqlite"
    database.touch(mode=0o600, exist_ok=False)
    try:
        source_bytes, sequence_bytes = source.read_bytes(), sequence_file.read_bytes()
        with closing(sqlite3.connect(database)) as db:
            db.row_factory = sqlite3.Row
            import_sql(db, source_bytes.decode("utf-8"))
            result = rehearse(db, baseline, json.loads(sequence_bytes))
        require(source.read_bytes() == source_bytes and sequence_file.read_bytes() == sequence_bytes, "Private inputs changed during rehearsal")
        provenance = {
            "sourceSha256": hashlib.sha256(source_bytes).hexdigest(),
            "sequenceCaptureSha256": hashlib.sha256(sequence_bytes).hexdigest(),
            "codeInputsSha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in (*MIGRATIONS, *(ROOT / name for name in content.PATCHES))},
        }
        with (output / "provenance.json").open("x") as file:
            os.chmod(output / "provenance.json", 0o600)
            json.dump(provenance, file, indent=2)
            file.write("\n")
        report = output / "result.json"
        with report.open("x") as file:
            os.chmod(report, 0o600)
            json.dump(result, file, indent=2)
            file.write("\n")
    except Exception as error:
        # Diagnostics can contain SQL/identities from trigger errors: private only.
        failure = output / "failure.txt"
        with failure.open("x") as file:
            os.chmod(failure, 0o600)
            file.write(f"{type(error).__name__}: {error}\n")
        # No raw SQL, row values, keys, identities, or private paths on stdout.
        raise RuntimeError("Offline rehearsal failed; partial copy retained privately. Diagnose before using a NEW output directory.") from None
    return result
