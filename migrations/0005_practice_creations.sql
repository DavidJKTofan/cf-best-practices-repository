-- Durable, actor-scoped idempotency receipts. Not part of public catalog/seed exports.
-- Keep receipts for as long as their practices: pruning them permits old retries to duplicate writes.
CREATE TABLE PracticeCreations (
	operation_key TEXT PRIMARY KEY NOT NULL,
	payload_hash TEXT NOT NULL,
	practice_id INTEGER NOT NULL UNIQUE REFERENCES BestPractices(practice_id),
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
PRAGMA optimize;
