import { HttpError, log, parseId } from './http';
import { PRACTICES_SQL, type Practice } from './practice-data';
import { ENUMS } from './practice-validation';
import { CONTENT_CACHE_TAG } from './public-content';

export const EDGE_CACHE_CONTROL = 'public, max-age=3600, stale-while-revalidate=86400';
export const PUBLIC_CORS = {
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
	'Access-Control-Allow-Headers': 'Accept',
	'Access-Control-Max-Age': '86400',
};

const ENUM_FILTERS: [string, string, string[]][] = [
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

async function listPractices(db: D1DatabaseSession, url: URL): Promise<Practice[]> {
	const params = url.searchParams;
	const conditions: string[] = [];
	const bindings: (string | number)[] = [];
	const search = params.get('search');
	if (search) {
		const pattern = `%${search.replace(/[\\%_]/g, '\\$&')}%`;
		const columns = ['bp.title', 'bp.description', 'bp.expression', 'bp.expressions_configuration_details', 'bp.prerequisites', 'bp.notes'];
		conditions.push(`(${columns.map((column) => `${column} LIKE ? ESCAPE '\\'`).join(' OR ')})`);
		bindings.push(...columns.map(() => pattern));
	}
	for (const [param, column] of [
		['categoryId', 'bp.category_id'],
		['featureId', 'bp.feature_id'],
	]) {
		const id = parseId(params.get(param));
		if (id) {
			conditions.push(`${column} = ?`);
			bindings.push(id);
		}
	}
	for (const [param, column, allowed] of ENUM_FILTERS) {
		const value = params.get(param);
		if (value && allowed.includes(value)) {
			conditions.push(`${column} = ?`);
			bindings.push(value);
		}
	}
	const where = conditions.length ? ` WHERE ${conditions.join(' AND ')}` : '';
	const { results, meta } = await db
		.prepare(`${PRACTICES_SQL}${where} ORDER BY bp.domain, category_name, bp.title`)
		.bind(...bindings)
		.all<Practice>();
	log('log', 'd1 query', {
		query: 'practices',
		filtered: conditions.length > 0,
		rows_read: meta.rows_read,
		duration_ms: meta.duration,
		served_by_region: meta.served_by_region,
		served_by_primary: meta.served_by_primary,
	});
	return results;
}

interface TaxonomyItem {
	id: number;
	name: string;
	feature_url?: string | null;
}
interface ReadRoute {
	handler: (db: D1DatabaseSession, url: URL) => Promise<Practice[] | TaxonomyItem[]>;
	tag: string;
	cacheControl: string;
}

export const READ_ROUTES: Record<string, ReadRoute | undefined> = {
	'/api/practices': { handler: listPractices, tag: CONTENT_CACHE_TAG, cacheControl: 'public, max-age=60, stale-while-revalidate=600' },
	'/api/categories': {
		handler: async (db) => (await db.prepare('SELECT category_id AS id, name FROM Categories ORDER BY name').all<TaxonomyItem>()).results,
		tag: 'taxonomy',
		cacheControl: 'public, max-age=300, stale-while-revalidate=3600',
	},
	'/api/features': {
		handler: async (db) =>
			(await db.prepare('SELECT feature_id AS id, name, feature_url FROM CloudflareFeatures ORDER BY name').all<TaxonomyItem>()).results,
		tag: 'taxonomy',
		cacheControl: 'public, max-age=300, stale-while-revalidate=3600',
	},
};

export async function enforceRateLimit(env: Env, key: string): Promise<void> {
	if (!env.MY_RATE_LIMITER) return;
	try {
		const { success } = await env.MY_RATE_LIMITER.limit({ key });
		if (!success) {
			log('warn', 'rate limited', { key });
			throw new HttpError(429, 'Rate limit exceeded. Please try again later.', { 'Retry-After': '60' });
		}
	} catch (err) {
		if (err instanceof HttpError) throw err;
		console.error(err); // Soft guard: fail open on limiter outages, not on an explicit rejection.
	}
}
