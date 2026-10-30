import type { Block, TypedContent } from './types';

export interface ReadingSection {
	id: string;
	title: string;
	paragraphs?: string[];
	items?: string[];
	ordered?: boolean;
	blocks?: Block[];
	diagram?: string;
}

// One type-to-section mapping for HTML and Markdown. Stored text never becomes markup.
export function readingSections(content: TypedContent): ReadingSection[] {
	const list = (id: string, title: string, items: string[], ordered = false): ReadingSection => ({ id, title, items, ordered });
	const sections: ReadingSection[] = [
		list('requires', 'Before you begin', content.applicability.requires),
		list('exclusions', 'Not for', content.applicability.excludes),
		list('dependencies', 'Dependencies and availability', content.applicability.dependencies),
	];
	if (content.type === 'rule-policy') {
		const b = content.body;
		sections.push(
			{ id: 'context', title: 'Rule context', paragraphs: [`Product: ${b.product}`, `Phase: ${b.phase}`, `Scope: ${b.scope}`] },
			list('availability', 'Plan and action availability', b.availability),
			list('conditions', 'Match conditions', b.conditions),
			{
				id: 'expression',
				title: 'Expression',
				blocks: [
					{
						kind: 'code',
						filename: 'Match expression',
						language: 'text',
						purpose: 'Conditions only; configure the action separately.',
						code: b.expression,
					},
				],
			},
			{ id: 'action', title: 'Action', paragraphs: [b.action] },
			list('rollout', 'Safe rollout', b.rollout, true),
			list('validation', 'Verify the result', b.validation, true),
			list('rollback', 'Rollback', b.rollback, true),
		);
	} else if (content.type === 'reference-architecture') {
		const b = content.body;
		sections.push(
			list('assumptions', 'Assumptions', b.assumptions),
			{ id: 'topology', title: 'Traffic path', diagram: b.diagramText },
			list('components', 'Components', b.components),
			list('flows', 'Request flow', b.flows, true),
			list('trust', 'Trust boundaries', b.trustBoundaries),
			list('routing', 'Routing and DNS', b.routingAndDns),
			list('identity', 'Identity and policy', b.identityPolicy),
			list('failures', 'Failure modes', b.failureModes),
			list('tradeoffs', 'Trade-offs', b.tradeoffs),
			list('validation', 'Verify the result', b.validation, true),
			list('rollback', 'Rollback', b.rollback, true),
		);
	} else if (content.type === 'implementation-guide') {
		const b = content.body;
		if ('variant' in b) {
			sections.push(
				{ id: 'task', title: 'Operational task', paragraphs: [b.task] },
				list('symptoms', 'Recognize the symptoms', b.symptoms),
				list('diagnostics', 'Read-only diagnosis', b.diagnostics, true),
				list('safe-changes', 'Approved, scoped changes', b.safeChanges, true),
				list('recovery', 'Recovery and escalation', b.recovery, true),
				list('validation', 'Success criteria', b.successCriteria, true),
				list('rollback', 'Rollback', b.rollback, true),
			);
		} else
			sections.push(
				list('prerequisites', 'Implementation prerequisites', b.prerequisites),
				list('steps', 'Implementation steps', b.steps, true),
				{ id: 'files', title: 'Files and configuration', blocks: b.artifacts },
				list('validation', 'Verify the result', b.validation, true),
				list('rollback', 'Rollback', b.rollback, true),
			);
	} else {
		sections.push(
			{ id: 'rationale', title: 'Why this pattern', paragraphs: [content.body.rationale] },
			{ id: 'guidance', title: 'Guidance', blocks: content.body.guidance },
			list('validation', 'Verify the result', content.body.validation, true),
		);
	}
	return sections.filter((s) => s.paragraphs?.length || s.items?.length || s.blocks?.length || s.diagram);
}

export const TYPE_LABELS: Record<string, string> = {
	'legacy-practice': 'Legacy practice',
	recommendation: 'Recommendation',
	'rule-policy': 'Rule / policy',
	'reference-architecture': 'Reference architecture',
	'implementation-guide': 'Implementation guide',
};
