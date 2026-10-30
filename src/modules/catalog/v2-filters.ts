import { CONTENT_TYPES } from '../../content/types';

export const V2_TYPES = ['legacy-practice', ...CONTENT_TYPES] as const;
export const V2_SORTS = ['title', 'newest'] as const;
export interface CatalogQuery {
	q: string;
	family: string;
	product: string;
	outcome: string;
	type: string;
	sort: (typeof V2_SORTS)[number];
	page: number;
	pageSize: number;
}
function integer(value: string | null, fallback: number, max: number): number {
	if (!value || !/^\d+$/.test(value)) return fallback;
	const number = Number(value);
	return number >= 1 ? Math.min(number, max) : fallback;
}
function slug(value: string | null): string {
	return value && value.length <= 80 && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value) ? value : '';
}
// Used before the cache AND by SQL. First duplicate wins; unknown/default state
// disappears from the key. No truncation based on SQL wildcard byte limits.
export function catalogQuery(url: URL): CatalogQuery {
	const p = url.searchParams;
	const q = [...(p.get('q') ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim()].slice(0, 200).join('').trim();
	const type = p.get('type') ?? '';
	return {
		q,
		family: slug(p.get('family')),
		product: slug(p.get('product')),
		outcome: slug(p.get('outcome')),
		type: V2_TYPES.some((value) => value === type) ? type : '',
		sort: p.get('sort') === 'newest' ? 'newest' : 'title',
		page: integer(p.get('page'), 1, 10000),
		pageSize: integer(p.get('pageSize'), 20, 50),
	};
}
export function catalogSearch(query: CatalogQuery, facets = false): string {
	const p = new URLSearchParams();
	for (const key of ['q', 'family', 'product', 'outcome', 'type'] as const) if (query[key]) p.set(key, query[key]);
	if (!facets) {
		if (query.sort !== 'title') p.set('sort', query.sort);
		if (query.page !== 1) p.set('page', String(query.page));
		if (query.pageSize !== 20) p.set('pageSize', String(query.pageSize));
	}
	return p.toString();
}
export function normalizeV2Request(request: Request): Request {
	const url = new URL(request.url);
	url.search = ['/api/v2/entries', '/api/v2/facets'].includes(url.pathname)
		? catalogSearch(catalogQuery(url), url.pathname === '/api/v2/facets')
		: '';
	const headers = new Headers(request.headers);
	headers.set('Accept', 'application/json');
	return new Request(url, { method: 'GET', headers });
}
