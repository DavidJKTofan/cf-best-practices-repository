#!/usr/bin/env python3
"""Sanitize an approved, private D1 SQL export. Local only; no remote operations.

Usage: npm run db:seed:refresh -- /private/path/export.sql [output.sql]
Never copy a full export into this repository. Review the generated catalog diff.
"""

import sqlite3
import sys
from pathlib import Path
from contextlib import closing
from catalog_integrity import verify_catalog

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_COLUMNS = {
    "Categories": ("category_id", "name", "description", "display_order"),
    "CloudflareFeatures": ("feature_id", "name", "feature_url", "subscription_level"),
    "BestPractices": ("practice_id", "title", "description", "domain", "category_id", "feature_id", "recommendation_level", "impact_level", "difficulty_level", "prerequisites", "expressions_configuration_details", "source_reference", "notes", "created_at", "updated_at", "expression"),
    "CatalogTaxa": ("kind", "slug", "label"),
    "CatalogTaxonAliases": ("kind", "alias", "slug"),
    "CatalogRevisions": ("revision_id", "practice_id", "schema_version", "content_type", "title", "summary", "primary_family", "primary_family_kind", "applicability_json", "body_json", "evidence", "maturity", "modified_at", "fact_verified_at", "review_due_at", "lifecycle_json"),
    "CatalogRevisionTaxa": ("revision_id", "kind", "slug"),
    "CatalogRevisionSources": ("revision_id", "position", "url", "title"),
    "CatalogPublications": ("practice_id", "revision_id", "published_at"),
}


def inserts(db, table, where=""):
    # All identifiers/conditions are hard-coded below, never command-line SQL.
    # A future private column on a public table must not leak via SELECT *.
    fields = PUBLIC_COLUMNS[table]
    names = ", ".join(f'"{name}"' for name in fields)
    rows = db.execute(f'SELECT {names} FROM "{table}" {where} ORDER BY 1').fetchall()
    for row in rows:
        quoted = [db.execute("SELECT quote(?)", (value,)).fetchone()[0] for value in row]
        yield f'INSERT INTO "{table}" ({names}) VALUES ({", ".join(quoted)});'


def public_sql(db):
    """Only current public snapshots. No drafts, other revisions, or receipts."""
    statements = ["-- Public catalog only; generated from a private export. Not a full backup."]
    for table in ("Categories", "CloudflareFeatures", "BestPractices"):
        statements.extend(inserts(db, table))
    statements.extend(inserts(db, "CatalogTaxa", """WHERE EXISTS (
        SELECT 1 FROM CatalogRevisionTaxa t JOIN CatalogEntries e ON e.published_revision_id = t.revision_id
        WHERE t.kind = CatalogTaxa.kind AND t.slug = CatalogTaxa.slug)"""))
    statements.extend(inserts(db, "CatalogTaxonAliases", """WHERE EXISTS (
        SELECT 1 FROM CatalogRevisionTaxa t JOIN CatalogEntries e ON e.published_revision_id = t.revision_id
        WHERE t.kind = CatalogTaxonAliases.kind AND t.slug = CatalogTaxonAliases.slug)"""))
    # Legacy identity is recreated by the BestPractices insert trigger. Do not
    # export draft-only reservations or private high-water sequences.
    for row in db.execute("SELECT practice_id FROM CatalogEntries WHERE legacy_practice_id IS NULL AND published_revision_id IS NOT NULL ORDER BY practice_id"):
        statements.append(f"INSERT INTO CatalogEntries (practice_id) VALUES ({int(row[0])});")
    for table in ("CatalogRevisions", "CatalogRevisionTaxa", "CatalogRevisionSources", "CatalogPublications"):
        statements.extend(inserts(db, table, "WHERE revision_id IN (SELECT published_revision_id FROM CatalogEntries WHERE published_revision_id IS NOT NULL)"))
    for row in db.execute("SELECT practice_id, published_revision_id FROM CatalogEntries WHERE published_revision_id IS NOT NULL ORDER BY practice_id"):
        statements.append(f"UPDATE CatalogEntries SET published_revision_id = {int(row[1])} WHERE practice_id = {int(row[0])};")
    return "\n".join(statements) + "\n"


def main():
    if len(sys.argv) not in (2, 3):
        raise SystemExit(__doc__)
    source = Path(sys.argv[1]).expanduser().resolve(strict=True)
    if source.is_relative_to(ROOT):
        raise SystemExit("Full exports must remain outside the repository")
    target = (Path(sys.argv[2]) if len(sys.argv) == 3 else ROOT / "initial_data.sql").expanduser().resolve()
    if target == source:
        raise SystemExit("Refusing to overwrite the private full backup")
    with closing(sqlite3.connect(":memory:")) as db:
        db.executescript(source.read_text())
        # Refuse old-schema exports rather than silently losing typed content.
        db.execute("SELECT published_revision_id FROM CatalogEntries LIMIT 0")
        sql = public_sql(db)
    # Prove the allowlist output loads under the real schema before touching the seed.
    with closing(sqlite3.connect(":memory:")) as clean:
        clean.row_factory = sqlite3.Row
        clean.execute("PRAGMA foreign_keys = ON")
        for migration in sorted((ROOT / "migrations").glob("*.sql")):
            clean.executescript(migration.read_text())
        clean.executescript(sql)
        verify_catalog(clean)
    target.write_text(sql)
    print("Wrote public catalog snapshot. Review the diff; full backups remain private.")


if __name__ == "__main__":
    main()
