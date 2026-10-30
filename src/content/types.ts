export const CONTENT_TYPES = ['recommendation', 'rule-policy', 'reference-architecture', 'implementation-guide'] as const;
export type ContentType = (typeof CONTENT_TYPES)[number];
export const EVIDENCE = ['unreviewed', 'public-docs', 'lab-tested'] as const;
export const MATURITY = ['unknown', 'ga', 'beta', 'early-access', 'announcement-only'] as const;
export type Block =
	{ kind: 'prose' | 'warning'; text: string } | { kind: 'code'; language: string; filename: string; code: string; purpose: string };

export interface RunbookBody {
	variant: 'operational-runbook';
	task: string;
	symptoms: string[];
	diagnostics: string[];
	safeChanges: string[];
	recovery: string[];
	successCriteria: string[];
	rollback: string[];
}

export interface BodyByType {
	recommendation: { rationale: string; guidance: Block[]; validation: string[] };
	'rule-policy': {
		product: string;
		phase: string;
		scope: string;
		conditions: string[];
		availability: string[];
		expression: string;
		action: string;
		rollout: string[];
		rollback: string[];
		validation: string[];
	};
	'reference-architecture': {
		assumptions: string[];
		components: string[];
		flows: string[];
		trustBoundaries: string[];
		routingAndDns: string[];
		identityPolicy: string[];
		failureModes: string[];
		tradeoffs: string[];
		diagramText: string;
		validation: string[];
		rollback: string[];
	};
	'implementation-guide':
		{ prerequisites: string[]; steps: string[]; artifacts: Block[]; validation: string[]; rollback: string[] } | RunbookBody;
}
export interface SharedContent {
	schemaVersion: 1;
	title: string;
	summary: string;
	primaryFamily: string;
	families: string[];
	products: string[];
	outcomes: string[];
	applicability: { requires: string[]; excludes: string[]; dependencies: string[] };
	sources: { url: string; title: string }[];
	evidence: (typeof EVIDENCE)[number];
	maturity: (typeof MATURITY)[number];
	modifiedAt: string | null;
	factVerifiedAt: string | null;
	reviewDueAt: string | null;
}
export type TypedContent = { [T in ContentType]: SharedContent & { type: T; body: BodyByType[T] } }[ContentType];
