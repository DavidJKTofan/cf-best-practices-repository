// Shared projection: JSON, HTML, Markdown, and discovery all describe the same D1 records.
export const PRACTICES_SQL = `
	SELECT
		bp.practice_id, bp.title, bp.description, bp.domain,
		bp.category_id, cat.name AS category_name,
		bp.feature_id, cf.name AS feature_name, cf.feature_url,
		bp.recommendation_level, bp.impact_level, bp.difficulty_level,
		bp.prerequisites, bp.expressions_configuration_details,
		bp.source_reference, bp.notes, bp.updated_at
	FROM BestPractices bp
	LEFT JOIN Categories cat ON bp.category_id = cat.category_id
	LEFT JOIN CloudflareFeatures cf ON bp.feature_id = cf.feature_id`;

export interface Practice {
	practice_id: number;
	title: string;
	description: string;
	domain: string;
	category_id: number | null;
	category_name: string | null;
	feature_id: number | null;
	feature_name: string | null;
	feature_url: string | null;
	recommendation_level: string | null;
	impact_level: string | null;
	difficulty_level: string | null;
	prerequisites: string | null;
	expressions_configuration_details: string | null;
	source_reference: string | null;
	notes: string | null;
	updated_at: string | null;
}
