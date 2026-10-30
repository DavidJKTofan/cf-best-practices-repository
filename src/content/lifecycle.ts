import { HttpError, parseId } from '../http';

export interface Lifecycle {
	state: 'active' | 'deprecated' | 'superseded';
	reason: string | null;
	supersededBy: number | null;
}
export function validateLifecycle(value: unknown): Lifecycle {
	if (!value || typeof value !== 'object' || Array.isArray(value)) throw new HttpError(400, 'Invalid lifecycle');
	const v = value as Record<string, unknown>;
	if (Object.keys(v).sort().join(',') !== 'reason,state,supersededBy') throw new HttpError(400, 'Invalid lifecycle');
	if (v.state === 'active' && v.reason === null && v.supersededBy === null) return { state: 'active', reason: null, supersededBy: null };
	if (
		typeof v.reason !== 'string' ||
		!v.reason.trim() ||
		v.reason.length > 2000 ||
		/\0|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(v.reason)
	)
		throw new HttpError(400, 'A public lifecycle reason is required');
	if (v.state === 'deprecated' && v.supersededBy === null) return { state: 'deprecated', reason: v.reason, supersededBy: null };
	if (v.state === 'superseded' && typeof v.supersededBy === 'number' && parseId(v.supersededBy))
		return { state: 'superseded', reason: v.reason, supersededBy: v.supersededBy };
	throw new HttpError(400, 'Invalid lifecycle');
}
