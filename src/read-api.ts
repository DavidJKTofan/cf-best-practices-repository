import { listPractices } from './modules/catalog/queries';
import { listCategories, listFeatures, type TaxonomyItem } from './modules/taxonomy/queries';
import { CONTENT_CACHE_CONTROL, CONTENT_CACHE_TAG, TAXONOMY_CACHE_CONTROL, TAXONOMY_CACHE_TAG } from './platform/cache';
import type { Practice } from './practice-data';
import { catalogFacets, getCatalogEntry, listCatalog } from './modules/catalog/v2-queries';

// Retain the original module exports for existing callers and the isolated Phase 0 proof.
export { normalizeApiRequest } from './modules/catalog/filters';
export { EDGE_CACHE_CONTROL } from './platform/cache';
export { PUBLIC_CORS } from './platform/public-http';
export { enforceRateLimit } from './platform/rate-limit';

interface LegacyReadRoute {
	handler: (db: D1DatabaseSession, url: URL) => Promise<Practice[] | TaxonomyItem[]>;
	tag: string;
	cacheControl: string;
	version?: 1;
}
interface V2ReadRoute {
	handler: typeof listCatalog | typeof getCatalogEntry | typeof catalogFacets;
	tag: string;
	cacheControl: string;
	version: 2;
}
type ReadRoute = LegacyReadRoute | V2ReadRoute;

export const READ_ROUTES: Record<string, ReadRoute | undefined> = {
	'/api/practices': { handler: listPractices, tag: CONTENT_CACHE_TAG, cacheControl: CONTENT_CACHE_CONTROL },
	'/api/categories': { handler: listCategories, tag: TAXONOMY_CACHE_TAG, cacheControl: TAXONOMY_CACHE_CONTROL },
	'/api/features': { handler: listFeatures, tag: TAXONOMY_CACHE_TAG, cacheControl: TAXONOMY_CACHE_CONTROL },
	'/api/v2/entries': { handler: listCatalog, tag: CONTENT_CACHE_TAG, cacheControl: CONTENT_CACHE_CONTROL, version: 2 },
	'/api/v2/facets': { handler: catalogFacets, tag: CONTENT_CACHE_TAG, cacheControl: CONTENT_CACHE_CONTROL, version: 2 },
};

export function resolveReadRoute(path: string): ReadRoute | undefined {
	if (/^\/api\/v2\/entries\/[1-9]\d*$/.test(path) && Number(path.split('/').at(-1)) <= 2147483647) {
		return { handler: getCatalogEntry, tag: CONTENT_CACHE_TAG, cacheControl: CONTENT_CACHE_CONTROL, version: 2 };
	}
	return READ_ROUTES[path];
}
