// Empty authoring scaffolds, not publishable guidance or entitlement claims.
export function template(type) {
	const list = ['Replace with reviewed guidance.'];
	const runbook = type === 'operational-runbook';
	if (runbook) type = 'implementation-guide';
	const bodies = {
		recommendation: { rationale: 'Explain why.', guidance: [{ kind: 'prose', text: 'Write sourced guidance.' }], validation: list },
		'rule-policy': {
			product: 'replace-product',
			phase: 'Specify the actual phase.',
			scope: 'Specify scope.',
			conditions: list,
			availability: list,
			expression: 'Replace with validated expression.',
			action: 'Specify action separately.',
			rollout: list,
			rollback: list,
			validation: list,
		},
		'reference-architecture': {
			assumptions: list,
			components: list,
			flows: list,
			trustBoundaries: list,
			routingAndDns: list,
			identityPolicy: list,
			failureModes: list,
			tradeoffs: list,
			diagramText: 'Describe traffic and trust boundaries.',
			validation: list,
			rollback: list,
		},
		'implementation-guide': {
			prerequisites: list,
			steps: list,
			artifacts: [
				{
					kind: 'code',
					language: 'text',
					filename: 'example.txt',
					purpose: 'Explain purpose and prerequisites.',
					code: 'Replace with tested configuration.',
				},
			],
			validation: list,
			rollback: list,
		},
	};
	return {
		schemaVersion: 1,
		type,
		title: 'Untitled working copy',
		summary: 'Write an accurate summary.',
		primaryFamily: 'application-services',
		families: ['application-services'],
		products: ['replace-product'],
		outcomes: [],
		applicability: { requires: list, excludes: [], dependencies: [] },
		sources: [{ url: 'https://developers.cloudflare.com/', title: 'Replace with the specific public source.' }],
		evidence: 'unreviewed',
		maturity: 'unknown',
		modifiedAt: null,
		factVerifiedAt: null,
		reviewDueAt: null,
		body: runbook
			? {
					variant: 'operational-runbook',
					task: 'Define the operational task and approval boundary.',
					symptoms: list,
					diagnostics: list,
					safeChanges: list,
					recovery: list,
					successCriteria: list,
					rollback: list,
				}
			: bodies[type],
	};
}
