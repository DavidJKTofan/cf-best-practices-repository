import { HttpError } from '../http';
import { CONTENT_TYPES, EVIDENCE, MATURITY, type Block, type TypedContent } from './types';

function fail(field: string): never {
	throw new HttpError(400, `Invalid catalog content: ${field}`);
}
function object(value: unknown, keys: string[], field: string): Record<string, unknown> {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return fail(field);
	const record = value as Record<string, unknown>;
	if (Object.keys(record).some((key) => !keys.includes(key)) || keys.some((key) => !Object.hasOwn(record, key))) return fail(field);
	return record;
}
function text(value: unknown, field: string, max = 5000): string {
	if (
		typeof value !== 'string' ||
		!value.trim() ||
		value.length > max ||
		/\0|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)
	) {
		return fail(field);
	}
	return value;
}
function list(value: unknown, field: string, min = 1): string[] {
	if (!Array.isArray(value) || value.length < min || value.length > 20) return fail(field);
	return value.map((item) => text(item, field, 2000));
}
function slugs(value: unknown, field: string, min = 0): string[] {
	const values = list(value, field, min);
	if (values.some((item) => !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(item) || item.length > 80) || new Set(values).size !== values.length)
		return fail(field);
	return values;
}
function choice<const T extends readonly string[]>(value: unknown, allowed: T, field: string): T[number] {
	if (typeof value !== 'string' || !allowed.includes(value)) return fail(field);
	return value as T[number];
}
function date(value: unknown, field: string): string | null {
	if (value === null) return null;
	if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return fail(field);
	const parsed = new Date(`${value}T00:00:00Z`);
	if (!Number.isFinite(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== value) return fail(field);
	return value;
}
function blocks(value: unknown, field: string): Block[] {
	if (!Array.isArray(value) || value.length < 1 || value.length > 30) return fail(field);
	return value.map((item: unknown) => {
		if (item && typeof item === 'object' && 'kind' in item && (item.kind === 'prose' || item.kind === 'warning')) {
			const block = object(item, ['kind', 'text'], field);
			return { kind: item.kind, text: text(block.text, field) };
		}
		const block = object(item, ['kind', 'language', 'filename', 'code', 'purpose'], field);
		if (block.kind !== 'code') return fail(field);
		return {
			kind: 'code',
			language: text(block.language, field, 40),
			filename: text(block.filename, field, 200),
			code: text(block.code, field, 10000),
			purpose: text(block.purpose, field, 2000),
		};
	});
}

// Exact, shallow schemas bound nesting; no executable MDX/HTML/SVG block types.
// Call only after the existing streamed 64 KiB parser on future write routes.
export function validateContent(value: unknown): TypedContent {
	const root = object(
		value,
		[
			'schemaVersion',
			'type',
			'title',
			'summary',
			'primaryFamily',
			'families',
			'products',
			'outcomes',
			'applicability',
			'sources',
			'evidence',
			'maturity',
			'modifiedAt',
			'factVerifiedAt',
			'reviewDueAt',
			'body',
		],
		'envelope',
	);
	if (root.schemaVersion !== 1) return fail('schemaVersion');
	const type = choice(root.type, CONTENT_TYPES, 'type');
	const applicability = object(root.applicability, ['requires', 'excludes', 'dependencies'], 'applicability');
	const families = slugs(root.families, 'families', 1);
	const primaryFamily = slugs([root.primaryFamily], 'primaryFamily', 1)[0];
	if (!families.includes(primaryFamily)) return fail('primaryFamily');
	if (!Array.isArray(root.sources) || root.sources.length < 1 || root.sources.length > 16) return fail('sources');
	const sources = root.sources.map((item: unknown) => {
		const source = object(item, ['url', 'title'], 'sources');
		const url = text(source.url, 'sources.url', 1000);
		try {
			const parsed = new URL(url);
			if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password)
				return fail('sources.url');
		} catch {
			return fail('sources.url');
		}
		return { url, title: text(source.title, 'sources.title', 500) };
	});
	const shared = {
		schemaVersion: 1 as const,
		title: text(root.title, 'title', 500),
		summary: text(root.summary, 'summary', 500),
		primaryFamily,
		families,
		products: slugs(root.products, 'products', 1),
		outcomes: slugs(root.outcomes, 'outcomes'),
		applicability: {
			requires: list(applicability.requires, 'requires'),
			excludes: list(applicability.excludes, 'excludes', 0),
			dependencies: list(applicability.dependencies, 'dependencies', 0),
		},
		sources,
		evidence: choice(root.evidence, EVIDENCE, 'evidence'),
		maturity: choice(root.maturity, MATURITY, 'maturity'),
		modifiedAt: date(root.modifiedAt, 'modifiedAt'),
		factVerifiedAt: date(root.factVerifiedAt, 'factVerifiedAt'),
		reviewDueAt: date(root.reviewDueAt, 'reviewDueAt'),
	};
	if (shared.evidence === 'unreviewed' ? shared.factVerifiedAt !== null : shared.factVerifiedAt === null) return fail('factVerifiedAt');
	let result: TypedContent;
	if (type === 'recommendation') {
		const b = object(root.body, ['rationale', 'guidance', 'validation'], 'body');
		result = {
			...shared,
			type,
			body: {
				rationale: text(b.rationale, 'rationale'),
				guidance: blocks(b.guidance, 'guidance'),
				validation: list(b.validation, 'validation'),
			},
		};
	} else if (type === 'rule-policy') {
		const b = object(
			root.body,
			['product', 'phase', 'scope', 'conditions', 'availability', 'expression', 'action', 'rollout', 'rollback', 'validation'],
			'body',
		);
		const product = slugs([b.product], 'product', 1)[0];
		if (!shared.products.includes(product)) return fail('product');
		result = {
			...shared,
			type,
			body: {
				product,
				phase: text(b.phase, 'phase', 200),
				scope: text(b.scope, 'scope', 2000),
				conditions: list(b.conditions, 'conditions'),
				availability: list(b.availability, 'availability'),
				expression: text(b.expression, 'expression'),
				action: text(b.action, 'action', 2000),
				rollout: list(b.rollout, 'rollout'),
				rollback: list(b.rollback, 'rollback'),
				validation: list(b.validation, 'validation'),
			},
		};
	} else if (type === 'reference-architecture') {
		const b = object(
			root.body,
			[
				'assumptions',
				'components',
				'flows',
				'trustBoundaries',
				'routingAndDns',
				'identityPolicy',
				'failureModes',
				'tradeoffs',
				'diagramText',
				'validation',
				'rollback',
			],
			'body',
		);
		result = {
			...shared,
			type,
			body: {
				assumptions: list(b.assumptions, 'assumptions'),
				components: list(b.components, 'components'),
				flows: list(b.flows, 'flows'),
				trustBoundaries: list(b.trustBoundaries, 'trustBoundaries'),
				routingAndDns: list(b.routingAndDns, 'routingAndDns'),
				identityPolicy: list(b.identityPolicy, 'identityPolicy'),
				failureModes: list(b.failureModes, 'failureModes'),
				tradeoffs: list(b.tradeoffs, 'tradeoffs'),
				diagramText: text(b.diagramText, 'diagramText'),
				validation: list(b.validation, 'validation'),
				rollback: list(b.rollback, 'rollback'),
			},
		};
	} else if (root.body && typeof root.body === 'object' && 'variant' in root.body) {
		const b = object(
			root.body,
			['variant', 'task', 'symptoms', 'diagnostics', 'safeChanges', 'recovery', 'successCriteria', 'rollback'],
			'body',
		);
		if (b.variant !== 'operational-runbook') return fail('variant');
		result = {
			...shared,
			type,
			body: {
				variant: 'operational-runbook',
				task: text(b.task, 'task'),
				symptoms: list(b.symptoms, 'symptoms'),
				diagnostics: list(b.diagnostics, 'diagnostics'),
				safeChanges: list(b.safeChanges, 'safeChanges'),
				recovery: list(b.recovery, 'recovery'),
				successCriteria: list(b.successCriteria, 'successCriteria'),
				rollback: list(b.rollback, 'rollback'),
			},
		};
	} else {
		const b = object(root.body, ['prerequisites', 'steps', 'artifacts', 'validation', 'rollback'], 'body');
		result = {
			...shared,
			type,
			body: {
				prerequisites: list(b.prerequisites, 'prerequisites'),
				steps: list(b.steps, 'steps'),
				artifacts: blocks(b.artifacts, 'artifacts'),
				validation: list(b.validation, 'validation'),
				rollback: list(b.rollback, 'rollback'),
			},
		};
	}
	if (new TextEncoder().encode(JSON.stringify(result)).byteLength > 65536) return fail('64 KiB limit');
	return result;
}
