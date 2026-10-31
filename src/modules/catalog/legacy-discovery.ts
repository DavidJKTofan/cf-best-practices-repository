import { ENUMS } from '../../practice-validation';

// Recorded legacy classifications are not native product-family assignments.
export const LEGACY_FILTERS = [
	{ key: 'domain', column: 'bp.domain', values: ENUMS.domain },
	{ key: 'level', column: 'bp.recommendation_level', values: ENUMS.recommendation_level },
	{ key: 'impact', column: 'bp.impact_level', values: ENUMS.impact_level },
	{ key: 'difficulty', column: 'bp.difficulty_level', values: ENUMS.difficulty_level },
] as const;
export const LEGACY_FILTER_KEYS = ['categoryId', 'featureId', 'domain', 'level', 'impact', 'difficulty'] as const;

export const CATALOG_FROM = `PublishedCatalog v
	LEFT JOIN BestPractices bp ON v.schema_version = 0 AND v.revision_id IS NULL AND bp.practice_id = v.practice_id
	LEFT JOIN Categories cat ON cat.category_id = bp.category_id
	LEFT JOIN CloudflareFeatures cf ON cf.feature_id = bp.feature_id`;
export const CATALOG_COLUMNS = `v.*, bp.domain AS legacy_domain,
	bp.category_id AS legacy_category_id, cat.name AS legacy_category,
	bp.feature_id AS legacy_feature_id, cf.name AS legacy_feature,
	bp.recommendation_level AS legacy_level, bp.impact_level AS legacy_impact, bp.difficulty_level AS legacy_difficulty`;

export interface LegacyColumns {
	legacy_domain: string | null;
	legacy_category_id: number | null;
	legacy_category: string | null;
	legacy_feature_id: number | null;
	legacy_feature: string | null;
	legacy_level: string | null;
	legacy_impact: string | null;
	legacy_difficulty: string | null;
}
export interface LegacyFacet {
	value: string;
	label: string;
	count: number;
}
export const LEGACY_FACET_GROUPS = ['categories', 'features', 'domains', 'levels', 'impacts', 'difficulties'] as const;
export type LegacyFacets = Record<(typeof LEGACY_FACET_GROUPS)[number], LegacyFacet[]>;
export const emptyLegacyFacets = (): LegacyFacets => ({
	categories: [],
	features: [],
	domains: [],
	levels: [],
	impacts: [],
	difficulties: [],
});

// Expand six scalar classifications from each matched summary, not six copies of
// PublishedCatalog's compound view (which exceeds workerd's compound SELECT limit).
// JSON is constructed by SQLite, never parsed from stored/user-authored JSON.
export function legacyFacetsSql(where: string): string {
	const groups = [
		['categories', 'bp.category_id', 'cat.name'],
		['features', 'bp.feature_id', 'cf.name'],
		['domains', 'bp.domain', 'bp.domain'],
		['levels', 'bp.recommendation_level', 'bp.recommendation_level'],
		['impacts', 'bp.impact_level', 'bp.impact_level'],
		['difficulties', 'bp.difficulty_level', 'bp.difficulty_level'],
	];
	return `SELECT facet.key AS kind, json_extract(facet.value, '$[0]') AS value,
		json_extract(facet.value, '$[1]') AS label, COUNT(*) AS count
		FROM ${CATALOG_FROM}
		CROSS JOIN json_each(json_object(${groups.map(([kind, value, label]) => `'${kind}', json_array(CAST(${value} AS TEXT), ${label})`).join(', ')})) facet
		${where}${where ? ' AND' : ' WHERE'} json_extract(facet.value, '$[0]') IS NOT NULL AND json_extract(facet.value, '$[1]') IS NOT NULL
		GROUP BY kind, json_extract(facet.value, '$[0]'), json_extract(facet.value, '$[1]')
		ORDER BY kind, label COLLATE NOCASE, value`;
}
