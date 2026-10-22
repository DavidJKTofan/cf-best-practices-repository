-- Keep an explicitly authored Rules expression separate from configuration prose.
-- Existing records remain compatible and display as configuration until reviewed.
ALTER TABLE BestPractices ADD COLUMN expression TEXT CHECK (expression IS NULL OR length(expression) <= 5000);
