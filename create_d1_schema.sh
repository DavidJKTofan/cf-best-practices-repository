#!/bin/bash

# --- Configuration ---
# Set the name of your D1 Database as configured in your wrangler.toml or Cloudflare dashboard
DATABASE_NAME="D1_DB_L7_BEST_PRACTICES"

# --- Helper Function ---
execute_sql() {
    local sql_command=$1
    echo "Executing: $sql_command"
    # Use --json for potentially cleaner error handling if needed, but default output is fine for success/failure
    npx wrangler d1 execute "$DATABASE_NAME" --command "$sql_command" --remote
    # Check exit code
    if [ $? -ne 0 ]; then
        echo "Error executing command: $sql_command" >&2
        exit 1 # Exit script on error
    fi
    # Add a small delay to prevent potential rate limiting on rapid commands
    sleep 1
}

# --- Schema Creation ---
echo "Starting D1 schema creation for database: $DATABASE_NAME"

# Create D1 database
npx wrangler d1 create $DATABASE_NAME --location weur

# Create Categories Table
execute_sql "CREATE TABLE Categories ( category_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, description TEXT );"

# Create CloudflareFeatures Table
execute_sql "CREATE TABLE CloudflareFeatures ( feature_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, feature_url TEXT );"

# Create BestPractices Table
execute_sql "CREATE TABLE BestPractices ( practice_id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT NOT NULL, area TEXT NOT NULL CHECK(area IN ('Security', 'Performance', 'Reliability', 'General')), category_id INTEGER, feature_id INTEGER, recommendation_level TEXT CHECK(recommendation_level IN ('Mandatory', 'Recommended', 'Optional', 'Situational')), expressions_configuration_details TEXT, source_reference TEXT, notes TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (category_id) REFERENCES Categories(category_id), FOREIGN KEY (feature_id) REFERENCES CloudflareFeatures(feature_id) );"

# Create ZoneImplementations Table (Optional)
# execute_sql "CREATE TABLE ZoneImplementations ( implementation_id INTEGER PRIMARY KEY AUTOINCREMENT, zone_id TEXT NOT NULL, practice_id INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('Implemented', 'Not Implemented', 'Needs Review', 'Not Applicable')), implementation_notes TEXT, last_verified DATETIME, FOREIGN KEY (practice_id) REFERENCES BestPractices(practice_id), UNIQUE(zone_id, practice_id) );"

# Create Indexes (Optional but Recommended)
execute_sql "CREATE INDEX idx_bestpractices_category ON BestPractices(category_id);"
execute_sql "CREATE INDEX idx_bestpractices_feature ON BestPractices(feature_id);"
# execute_sql "CREATE INDEX idx_zoneimplementations_zone ON ZoneImplementations(zone_id);"
# execute_sql "CREATE INDEX idx_zoneimplementations_practice ON ZoneImplementations(practice_id);"

# Create Trigger for updated_at (SQLite syntax might vary slightly in execution context, test carefully)
# Note: Multi-line SQL might require different formatting or --file flag with wrangler
UPDATE_TRIGGER_SQL="CREATE TRIGGER update_bestpractices_updated_at AFTER UPDATE ON BestPractices FOR EACH ROW BEGIN UPDATE BestPractices SET updated_at = CURRENT_TIMESTAMP WHERE practice_id = OLD.practice_id; END;"
execute_sql "$UPDATE_TRIGGER_SQL"

echo "--- D1 Schema Creation Script Finished ---"
exit 0
