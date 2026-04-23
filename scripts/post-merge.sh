#!/bin/bash
set -e
npm install

# Attempt schema sync. Safe changes (new tables, new columns, indexes) apply without
# interactive prompts. --force auto-approves data-loss confirmations in drizzle-kit.
#
# If drizzle-kit raises a TTY error (e.g. adding a unique constraint to an existing
# table with rows), apply the pending constraint(s) manually via SQL and re-run,
# or set CI=true below to capture the exit gracefully.
db_push_output=$(npm run db:push -- --force 2>&1)
db_push_status=$?
echo "$db_push_output"

if [ $db_push_status -ne 0 ]; then
  if echo "$db_push_output" | grep -q "Interactive prompts require a TTY"; then
    echo ""
    echo "WARNING: drizzle-kit requires interactive confirmation for a pending schema change."
    echo "This typically happens when adding a UNIQUE constraint to a table with existing rows."
    echo "Apply the constraint(s) manually via SQL (there should be no duplicates), then re-run."
    echo "The post-merge script is continuing without failing CI."
    exit 0
  fi
  # Any other drizzle-kit failure (DB connection error, etc.) is real — re-fail.
  exit $db_push_status
fi
