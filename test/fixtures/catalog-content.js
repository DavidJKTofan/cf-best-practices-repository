// Synthetic schema fixtures, not deployable Cloudflare guidance or pilot publication.
export function contentFixture(type = 'recommendation') {
	const bodies = {
		recommendation: {
			rationale: 'Fixture rationale.',
			guidance: [{ kind: 'prose', text: 'Fixture guidance.' }],
			validation: ['Check fixture.'],
		},
		'rule-policy': {
			product: 'waf',
			phase: 'fixture-phase',
			scope: 'Fixture hostname only.',
			conditions: ['Validate expected fixture traffic.'],
			availability: ['Verify plan and phase before use.'],
			expression: '(http.host eq "example.com")',
			action: 'Fixture only; verify availability.',
			rollout: ['Observe fixture.'],
			rollback: ['Disable fixture.'],
			validation: ['Check fixture.'],
		},
		'reference-architecture': {
			assumptions: ['Fixture scope.'],
			components: ['Fixture component.'],
			flows: ['Browser -> fixture.'],
			trustBoundaries: ['Authenticate fixture.'],
			routingAndDns: ['Fixture hostname and route.'],
			identityPolicy: ['Fixture identity provider and authorization.'],
			failureModes: ['Fixture outage.'],
			tradeoffs: ['Fixture trade-off.'],
			diagramText: 'Browser -> edge -> fixture',
			validation: ['Check fixture.'],
			rollback: ['Revert fixture.'],
		},
		'implementation-guide': {
			prerequisites: ['Fixture binding.'],
			steps: ['Apply fixture.'],
			artifacts: [
				{
					kind: 'code',
					language: 'typescript',
					filename: 'fixture.ts',
					code: 'export const fixture = true;',
					purpose: 'Schema fixture only.',
				},
			],
			validation: ['Check fixture.'],
			rollback: ['Revert fixture.'],
		},
	};
	return {
		schemaVersion: 1,
		type,
		title: `Fixture ${type}`,
		summary: 'Synthetic catalog fixture.',
		primaryFamily:
			type === 'reference-architecture'
				? 'cloudflare-one'
				: type === 'implementation-guide'
					? 'developer-platform'
					: 'application-services',
		families: [
			type === 'reference-architecture'
				? 'cloudflare-one'
				: type === 'implementation-guide'
					? 'developer-platform'
					: 'application-services',
		],
		products: type === 'reference-architecture' ? ['access', 'tunnel'] : type === 'implementation-guide' ? ['d1', 'workers'] : ['waf'],
		outcomes: [],
		applicability: { requires: ['Validate fixture scope.'], excludes: [], dependencies: [] },
		sources: [{ url: 'https://developers.cloudflare.com/', title: 'Public source fixture' }],
		evidence: 'unreviewed',
		maturity: 'unknown',
		modifiedAt: null,
		factVerifiedAt: null,
		reviewDueAt: null,
		body: bodies[type],
	};
}
