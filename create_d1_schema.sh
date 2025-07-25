#!/bin/bash

# --- Configuration ---
DATABASE_NAME="D1_DB_L7_BEST_PRACTICES"
LOG_FILE="d1_schema_creation.log"
ENVIRONMENT="remote" # Default to remote deployment

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --local) ENVIRONMENT="local" ;;
        --remote) ENVIRONMENT="remote" ;;
        --help) 
            echo "Usage: $0 [--local|--remote]"
            echo "  --local  Create and initialize local D1 database"
            echo "  --remote Deploy and initialize D1 database to Cloudflare (default)"
            exit 0
            ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# --- Helper Functions ---
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

execute_sql() {
    local sql_command=$1
    log_message "INFO" "Executing: $sql_command"
    if [ "$ENVIRONMENT" = "local" ]; then
        output=$(npx wrangler d1 execute "$DATABASE_NAME" --command "$sql_command" --local 2>&1)
    else
        output=$(npx wrangler d1 execute "$DATABASE_NAME" --command "$sql_command" --remote 2>&1)
    fi
    local status=$?
    if [ $status -ne 0 ]; then
        log_message "ERROR" "Failed executing command: $sql_command"
        log_message "ERROR" "Output: $output"
        return 1
    fi
    log_message "INFO" "Command executed successfully"
    sleep 1
}

# --- Schema Creation ---
log_message "INFO" "Starting D1 schema creation for database: $DATABASE_NAME"

# Delete existing database if it exists
# log_message "INFO" "Attempting to delete existing database..."
# npx wrangler d1 delete "$DATABASE_NAME" --force 2>/dev/null || true
log_message "INFO" "Creating new D1 database in $ENVIRONMENT environment..."

# Create new D1 database
if [ "$ENVIRONMENT" = "local" ]; then
    # For local development, create the database in the .wrangler folder
    mkdir -p .wrangler/state/d1
    npx wrangler d1 create "$DATABASE_NAME" --local
else
    # For remote deployment, create the database in Cloudflare
    npx wrangler d1 create "$DATABASE_NAME" --location weur
fi

if [ $? -ne 0 ]; then
    log_message "ERROR" "Failed to create database in $ENVIRONMENT environment"
    exit 1
fi

# Create Categories Table
execute_sql "DROP TABLE IF EXISTS Categories;
CREATE TABLE Categories ( 
    category_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    name TEXT NOT NULL UNIQUE, 
    description TEXT,
    display_order INTEGER DEFAULT 0
);" || exit 1

# Create CloudflareFeatures Table
execute_sql "DROP TABLE IF EXISTS CloudflareFeatures;
CREATE TABLE CloudflareFeatures ( 
    feature_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    name TEXT NOT NULL UNIQUE, 
    feature_url TEXT,
    subscription_level TEXT CHECK(subscription_level IN ('Free', 'Pro', 'Business', 'Enterprise', 'Paid Add-On'))
);" || exit 1

# Create BestPractices Table
execute_sql "DROP TABLE IF EXISTS BestPractices;
CREATE TABLE BestPractices ( 
    practice_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    title TEXT NOT NULL, 
    description TEXT NOT NULL, 
    domain TEXT NOT NULL CHECK(domain IN ('Security', 'Performance', 'Reliability', 'General')), 
    category_id INTEGER, 
    feature_id INTEGER, 
    recommendation_level TEXT CHECK(recommendation_level IN ('Mandatory', 'Recommended', 'Optional', 'Situational')),
    impact_level TEXT CHECK(impact_level IN ('High', 'Medium', 'Low')),
    difficulty_level TEXT CHECK(difficulty_level IN ('Easy', 'Medium', 'Complex', NULL)),
    prerequisites TEXT,
    expressions_configuration_details TEXT, 
    source_reference TEXT, 
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP, 
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, 
    FOREIGN KEY (category_id) REFERENCES Categories(category_id), 
    FOREIGN KEY (feature_id) REFERENCES CloudflareFeatures(feature_id) 
);" || exit 1

# Create Indexes
log_message "INFO" "Creating indexes..."
execute_sql "CREATE INDEX idx_bestpractices_category ON BestPractices(category_id);" || exit 1
execute_sql "CREATE INDEX idx_bestpractices_feature ON BestPractices(feature_id);" || exit 1
execute_sql "CREATE INDEX idx_bestpractices_domain ON BestPractices(domain);" || exit 1
execute_sql "CREATE INDEX idx_bestpractices_impact ON BestPractices(impact_level);" || exit 1

# Create Trigger for updated_at
# log_message "INFO" "Creating triggers..."
# UPDATE_TRIGGER_SQL="CREATE TRIGGER IF NOT EXISTS update_bestpractices_updated_at AFTER UPDATE ON BestPractices FOR EACH ROW BEGIN UPDATE BestPractices SET updated_at = CURRENT_TIMESTAMP WHERE practice_id = OLD.practice_id; END;"
# execute_sql "$UPDATE_TRIGGER_SQL" || exit 1

log_message "INFO" "Uploading initial data..."
if [ "$ENVIRONMENT" = "local" ]; then
    output=$(npx wrangler d1 execute "$DATABASE_NAME" --file=./initial_data.sql --local 2>&1)
else
    output=$(npx wrangler d1 execute "$DATABASE_NAME" --file=./initial_data.sql --remote 2>&1)
fi
status=$?
if [ $status -ne 0 ]; then
    log_message "ERROR" "Failed to upload initial data in $ENVIRONMENT environment"
    log_message "ERROR" "Output: $output"
    exit 1
fi
log_message "INFO" "Initial data uploaded successfully in $ENVIRONMENT environment"

log_message "INFO" "--- D1 Schema Creation Script Finished Successfully ---"
exit 0
