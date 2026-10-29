import { HttpError, parseId } from './http';

export const ENUMS = {
	domain: ['Security', 'Performance', 'Reliability', 'General'],
	recommendation_level: ['Mandatory', 'Recommended', 'Optional', 'Situational'],
	impact_level: ['High', 'Medium', 'Low'],
	difficulty_level: ['Easy', 'Medium', 'Complex'],
};

const TEXT_LIMITS = {
	title: 500,
	description: 5000,
	prerequisites: 5000,
	expression: 5000,
	expressions_configuration_details: 5000,
	source_reference: 1000,
	notes: 5000,
};

export function validatePractice(input: unknown) {
	if (!input || typeof input !== 'object' || Array.isArray(input)) throw new HttpError(400, 'Request body must be a JSON object');
	const body = input as Record<string, unknown>;
	const errors: string[] = [];
	const text = (field: keyof typeof TEXT_LIMITS, required: boolean): string | null => {
		const raw = body[field];
		if (raw !== undefined && raw !== null && typeof raw !== 'string') {
			errors.push(`${field} must be a string`);
			return null;
		}
		const value = (raw ?? '').replace(/\0/g, '').trim();
		if (!value) {
			if (required) errors.push(`${field} is required`);
			return null;
		}
		if (value.length > TEXT_LIMITS[field]) errors.push(`${field} must be at most ${TEXT_LIMITS[field]} characters`);
		return value;
	};
	const oneOf = (field: keyof typeof ENUMS, required: boolean): string | null => {
		const value = body[field];
		if (value === undefined || value === null || value === '') {
			if (required) errors.push(`${field} is required`);
			return null;
		}
		if (typeof value !== 'string' || !ENUMS[field].includes(value)) {
			errors.push(`${field} must be one of: ${ENUMS[field].join(', ')}`);
			return null;
		}
		return value;
	};
	const id = (field: 'category_id' | 'feature_id'): number | null => {
		const value = parseId(body[field]);
		if (!value) errors.push(`${field} must be a positive integer`);
		return value;
	};

	// Fixed key order is also the canonical representation used for idempotency hashing.
	const practice = {
		title: text('title', true),
		description: text('description', true),
		domain: oneOf('domain', true),
		category_id: id('category_id'),
		feature_id: id('feature_id'),
		recommendation_level: oneOf('recommendation_level', true),
		impact_level: oneOf('impact_level', true),
		difficulty_level: oneOf('difficulty_level', false),
		prerequisites: text('prerequisites', false),
		expression: text('expression', false),
		expressions_configuration_details: text('expressions_configuration_details', false),
		source_reference: text('source_reference', true),
		notes: text('notes', false),
	};
	if (practice.source_reference) {
		let protocol: string | undefined;
		try {
			protocol = new URL(practice.source_reference).protocol;
		} catch {}
		if (protocol !== 'https:' && protocol !== 'http:') errors.push('source_reference must be an http(s) URL');
	}
	if (errors.length) throw new HttpError(400, errors.join('; '));
	return practice;
}

export type PracticeInput = ReturnType<typeof validatePractice>;
