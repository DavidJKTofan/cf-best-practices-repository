import { parseId } from '../../http';
import { ENUMS } from '../../practice-validation';

export const ENUM_FILTERS: [string, string, string[]][] = [
	['area', 'bp.domain', ENUMS.domain],
	['level', 'bp.recommendation_level', ENUMS.recommendation_level],
	['impact', 'bp.impact_level', ENUMS.impact_level],
];

// Both the cache key and SQL consume this same canonical set of effective filters.
export function normalizeApiRequest(request: Request): Request {
	const url = new URL(request.url);
	const params = url.searchParams;
	const normalized = new URLSearchParams();
	if (url.pathname === '/api/practices') {
		const search = (params.get('search') ?? '').replace(/\0/g, '').trim().slice(0, 200);
		if (search) normalized.set('search', search);
		for (const name of ['categoryId', 'featureId']) {
			const id = parseId(params.get(name));
			if (id) normalized.set(name, String(id));
		}
		for (const [name, , allowed] of ENUM_FILTERS) {
			const value = params.get(name);
			if (value && allowed.includes(value)) normalized.set(name, value);
		}
	}
	url.search = normalized.toString();
	return new Request(url, { method: 'GET', headers: request.headers });
}
