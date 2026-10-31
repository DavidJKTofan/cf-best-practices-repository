import type { Practice } from '../../practice-data';
import { validateContent } from '../../content/validation';
import { validateLifecycle } from '../../content/lifecycle';
import type { LegacyColumns } from './legacy-discovery';

export interface CatalogRow extends LegacyColumns {
	practice_id: number;
	revision_id: number | null;
	schema_version: number;
	content_type: string;
	title: string;
	summary: string;
	primary_family: string | null;
	evidence: string;
	maturity: string;
	modified_at: string | null;
	fact_verified_at: string | null;
	review_due_at: string | null;
	v1_eligible: number;
	families_json: string;
	products_json: string;
	outcomes_json: string;
	lifecycle_json: string;
}
export function catalogSummary(row: CatalogRow) {
	let lifecycle;
	try {
		lifecycle = validateLifecycle(JSON.parse(row.lifecycle_json));
	} catch (err) {
		throw new Error('Invalid published lifecycle', { cause: err });
	}
	return {
		practiceId: row.practice_id,
		revisionId: row.revision_id,
		schemaVersion: row.schema_version,
		type: row.content_type,
		title: row.title,
		summary: row.summary,
		lifecycle,
		legacyClassification:
			row.schema_version === 0
				? {
						domain: row.legacy_domain,
						categoryId: row.legacy_category_id,
						category: row.legacy_category,
						featureId: row.legacy_feature_id,
						feature: row.legacy_feature,
						level: row.legacy_level,
						impact: row.legacy_impact,
						difficulty: row.legacy_difficulty,
					}
				: null,
		primaryFamily: row.primary_family,
		families: JSON.parse(row.families_json) as string[],
		products: JSON.parse(row.products_json) as string[],
		outcomes: JSON.parse(row.outcomes_json) as string[],
		evidence: row.evidence,
		maturity: row.maturity,
		modifiedAt: row.modified_at,
		factVerifiedAt: row.fact_verified_at,
		reviewDueAt: row.review_due_at,
		v1Eligible: row.v1_eligible === 1,
		canonicalPath: `/practices/${row.practice_id}`,
		detailPath: `/api/v2/entries/${row.practice_id}`,
	};
}
export function legacyDetail(row: CatalogRow, practice: Practice) {
	return {
		...catalogSummary(row),
		schemaVersion: 0 as const,
		type: 'legacy-practice' as const,
		applicability: null,
		sources: practice.source_reference ? [{ url: practice.source_reference, title: 'Recorded legacy source' }] : [],
		body: practice,
	};
}
export interface RevisionBodyRow {
	applicability_json: string;
	body_json: string;
}
export function typedDetail(row: CatalogRow, revision: RevisionBodyRow, sources: { url: string; title: string }[]) {
	const summary = catalogSummary(row);
	const content = validateContent({
		schemaVersion: row.schema_version,
		type: row.content_type,
		title: row.title,
		summary: row.summary,
		primaryFamily: row.primary_family,
		families: summary.families,
		products: summary.products,
		outcomes: summary.outcomes,
		evidence: row.evidence,
		maturity: row.maturity,
		modifiedAt: row.modified_at,
		factVerifiedAt: row.fact_verified_at,
		reviewDueAt: row.review_due_at,
		applicability: JSON.parse(revision.applicability_json),
		body: JSON.parse(revision.body_json),
		sources,
	});
	return { ...summary, ...content };
}

export type CatalogDetail = ReturnType<typeof legacyDetail> | ReturnType<typeof typedDetail>;
export type CatalogSummary = ReturnType<typeof catalogSummary>;
