#!/usr/bin/env python3
"""Offline catalog/active-patch verification; never reads or writes a remote database."""

import sqlite3
from pathlib import Path
from urllib.parse import urlparse
from catalog_integrity import verify_catalog

ROOT = Path(__file__).resolve().parents[1]
PATCHES = (
    "data/copyable-expressions.sql",
    "data/content-review-2026-10-29.sql",
    "data/catalog-taxonomy.sql",
    "data/phase5-products.sql",
)
TEXT_LIMITS = {
    "title": 500,
    "description": 5000,
    "prerequisites": 5000,
    "expression": 5000,
    "expressions_configuration_details": 5000,
    "source_reference": 1000,
    "notes": 5000,
}
ENUMS = {
    "domain": {"Security", "Performance", "Reliability", "General"},
    "recommendation_level": {"Mandatory", "Recommended", "Optional", "Situational"},
    "impact_level": {"High", "Medium", "Low"},
    "difficulty_level": {"Easy", "Medium", "Complex", None},
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def verify(db):
    require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "SQLite integrity check failed")
    require(not db.execute("PRAGMA foreign_key_check").fetchall(), "Foreign-key violations")
    verify_catalog(db)
    duplicates = db.execute(
        "SELECT LOWER(TRIM(title)) FROM BestPractices GROUP BY LOWER(TRIM(title)) HAVING COUNT(*) > 1"
    ).fetchall()
    require(not duplicates, "Duplicate titles")
    for row in db.execute("SELECT * FROM BestPractices"):
        label = f"practice {row['practice_id']}"
        for field in ("title", "description", "source_reference"):
            require(isinstance(row[field], str) and row[field].strip(), f"{label}: missing {field}")
        for field in ("category_id", "feature_id"):
            require(isinstance(row[field], int) and row[field] > 0, f"{label}: missing {field}")
        for field, values in ENUMS.items():
            require(row[field] in values, f"{label}: invalid {field}")
        for field, limit in TEXT_LIMITS.items():
            value = row[field]
            # Match the dashboard/Worker UTF-16 code-unit limits, not Python code-point counts.
            require(
                value is None or (isinstance(value, str) and len(value.encode("utf-16-le")) // 2 <= limit),
                f"{label}: invalid/oversize {field}",
            )
        source = urlparse(row["source_reference"])
        require(source.scheme == "https" and source.netloc, f"{label}: invalid HTTPS source")
        require("\x00" not in "".join(row[field] or "" for field in TEXT_LIMITS), f"{label}: NUL in text")


def snapshot(db):
    # Includes timestamps, indexes, all table contents, and AUTOINCREMENT sequences.
    return "\n".join(db.iterdump())


def apply_twice(db, sql, label):
    # Distinct deterministic clocks catch unconditional timestamp updates even in sub-second runs.
    db.create_function("current_timestamp", 0, lambda: "2099-01-01 00:00:00")
    db.executescript(sql)
    first = snapshot(db)
    db.create_function("current_timestamp", 0, lambda: "2099-01-02 00:00:00")
    db.executescript(sql)
    require(snapshot(db) == first, f"{label}: second application changes data, timestamps, or sequences")


def main():
    with sqlite3.connect(":memory:") as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        for path in sorted((ROOT / "migrations").glob("*.sql")):
            db.executescript(path.read_text())
        db.executescript((ROOT / "initial_data.sql").read_text())
        verify(db)
        original_ids = {row[0] for row in db.execute("SELECT practice_id FROM BestPractices")}
        for name in PATCHES:
            apply_twice(db, (ROOT / name).read_text(), name)
            verify(db)
            print(f"PASS {name}: repeat-run data/timestamps/sequences unchanged")
        current_ids = {row[0] for row in db.execute("SELECT practice_id FROM BestPractices")}
        require(original_ids <= current_ids, "Existing practice IDs were removed")
        require(
            db.execute("SELECT COUNT(*) FROM PracticeCreations").fetchone()[0] == 0,
            "Private creation receipts leaked into seed",
        )
        clearance = db.execute(
            "SELECT expressions_configuration_details FROM BestPractices WHERE practice_id = 72"
        ).fetchone()[0]
        require('http.request.clearance.uuid ne ""' in clearance, "Missing empty-clearance counter exclusion")
        profile = db.execute(
            "SELECT expressions_configuration_details, notes FROM BestPractices WHERE practice_id = 103"
        ).fetchone()
        require("Learn profile" in profile[0] and "uniqueness" in profile[1], "Missing profile learning/limitations")
        response_examples = db.execute(
            "SELECT expression FROM BestPractices WHERE title IN (?, ?)",
            ("Review Full-Transaction WAF Protection", "Contain Disclosures with Scoped Custom Response Rules"),
        ).fetchall()
        require(
            len(response_examples) == 2 and all(row[0] is None for row in response_examples),
            "Unverified response examples must not be executable",
        )
        counts = dict(db.execute("SELECT domain, COUNT(*) FROM BestPractices GROUP BY domain"))
        print(f"PASS integrity, taxonomy, sources, ratings, text limits, preserved IDs: {len(current_ids)} practices; {counts}")

    # Prove the checker detects an unconditional timestamp write (not merely duplicate rows).
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE probe (updated_at TEXT)")
        db.execute("INSERT INTO probe VALUES ('original')")
        try:
            apply_twice(db, "UPDATE probe SET updated_at = CURRENT_TIMESTAMP;", "self-test")
        except AssertionError:
            print("PASS verifier self-test: rejects non-idempotent timestamp updates")
        else:
            raise AssertionError("Verifier failed to detect timestamp drift")


if __name__ == "__main__":
    main()
