-- Read-only post-application checks. Run against the same database/persist-to used for the review.
-- The production snapshot had 102 practices; this review adds four, for 106 immediately afterward.
SELECT COUNT(*) AS practice_count FROM BestPractices;

-- Each violation query must return no rows. These also work on a freshly seeded local database.
PRAGMA foreign_key_check;

SELECT practice_id, title, 'missing required content or taxonomy' AS problem
FROM BestPractices
WHERE title IS NULL OR TRIM(title) = '' OR description IS NULL OR TRIM(description) = ''
	OR source_reference IS NULL OR source_reference NOT LIKE 'https://%'
	OR category_id IS NULL OR feature_id IS NULL OR impact_level IS NULL;

SELECT title, COUNT(*) AS duplicate_count
FROM BestPractices GROUP BY title HAVING COUNT(*) > 1;

SELECT practice_id, title, 'invalid rating' AS problem
FROM BestPractices
WHERE domain NOT IN ('Security', 'Performance', 'Reliability', 'General')
	OR recommendation_level IS NULL OR recommendation_level NOT IN ('Mandatory', 'Recommended', 'Optional', 'Situational')
	OR impact_level NOT IN ('High', 'Medium', 'Low')
	OR (difficulty_level IS NOT NULL AND difficulty_level NOT IN ('Easy', 'Medium', 'Complex'));

SELECT practice_id, title, 'exceeds API text limits' AS problem
FROM BestPractices
WHERE LENGTH(title) > 500 OR LENGTH(description) > 5000 OR LENGTH(prerequisites) > 5000
	OR LENGTH(expressions_configuration_details) > 5000 OR LENGTH(source_reference) > 1000 OR LENGTH(notes) > 5000;

SELECT practice_id, title, 'obsolete or invalid example' AS problem
FROM BestPractices
WHERE expressions_configuration_details LIKE '%$cf.botnets_command_and_control%'
	OR expressions_configuration_details LIKE '%http.request.uri.path ends_with%'
	OR expressions_configuration_details LIKE '%and <your rule condition>%'
	OR expressions_configuration_details LIKE '%entrypoint?dry_run=true%'
	OR expressions_configuration_details LIKE '%ip.geoip.%';
