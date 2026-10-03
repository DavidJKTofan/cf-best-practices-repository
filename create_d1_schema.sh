#!/usr/bin/env bash
# Creates/updates the D1 schema from versioned migrations (./migrations) and optionally loads seed data.
#
#   ./create_d1_schema.sh --local  [--seed]   # local development database (.wrangler/state)
#   ./create_d1_schema.sh --remote [--seed]   # production database
#
# The remote database must already exist and be configured in wrangler.jsonc. To create it:
#   npx wrangler d1 create D1_DB_L7_BEST_PRACTICES --location weur
#
# Migrations are idempotent and tracked in the d1_migrations table, so re-running is safe.
# Only use --seed on an empty database: initial_data.sql inserts fixed category/feature IDs.
set -euo pipefail

TARGET=""
SEED=false

usage() {
	sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--local | --remote) TARGET="$1" ;;
		--seed) SEED=true ;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			echo "Unknown option: $1" >&2
			usage >&2
			exit 1
			;;
	esac
	shift
done

if [[ -z "$TARGET" ]]; then
	echo "Choose a target database: --local or --remote" >&2
	usage >&2
	exit 1
fi

echo "==> Applying migrations ($TARGET)"
npx wrangler d1 migrations apply DB "$TARGET"

if [[ "$SEED" == true ]]; then
	echo "==> Loading initial_data.sql ($TARGET)"
	npx wrangler d1 execute DB "$TARGET" --file=./initial_data.sql
fi

# Refresh query planner statistics after schema/data changes
# (https://developers.cloudflare.com/d1/best-practices/use-indexes/#run-pragma-optimize)
echo "==> Running PRAGMA optimize ($TARGET)"
npx wrangler d1 execute DB "$TARGET" --command "PRAGMA optimize"

echo "==> Done"
