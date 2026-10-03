-- Migration number: 0002 	 Consolidate difficulty "High" into "Complex"
--
-- "High" is not a valid difficulty (allowed: Easy, Medium, Complex). It was accepted in production because the
-- original CHECK constraint was ineffective (see 0001). Idempotent: a no-op once no "High" rows remain.

UPDATE BestPractices
SET difficulty_level = 'Complex', updated_at = CURRENT_TIMESTAMP
WHERE difficulty_level = 'High';
