import { SITE_URL } from '../../content-rendering';
import { listingState } from './document-state';
import { catalogSearch, hasCatalogFilters } from './v2-filters';
import { catalogFacets, listCatalog } from './v2-queries';
import { starterCollection } from './starter-collections';
import { emptyLegacyFacets, LEGACY_FILTER_KEYS } from './legacy-discovery';

export async function loadListingPage(db: D1DatabaseSession, url: URL) {
	const query = listingState(url);
	const family = url.pathname.startsWith('/families/') ? query.family : '';
	const base = family ? `/families/${family}` : '/catalog';
	let result: Awaited<ReturnType<typeof listCatalog>> | undefined;
	let facets: Awaited<ReturnType<typeof catalogFacets>>['data'] = {
		types: [],
		families: [],
		products: [],
		outcomes: [],
		legacy: emptyLegacyFacets(),
	};
	let registry = facets;
	let familyLabel = '';
	let status = 200;
	let starter: Awaited<ReturnType<typeof starterCollection>> = null;
	try {
		const all = (await catalogFacets(db, new URL(`${SITE_URL}/api/v2/facets`))).data;
		registry = all;
		familyLabel = all.families.find((f) => f.slug === family)?.label ?? '';
		if (family && !familyLabel) status = 404;
		else {
			const effective = new URL(`${SITE_URL}/api/v2/entries?${catalogSearch(query)}`);
			[result, { data: facets }] = await Promise.all([
				listCatalog(db, effective),
				hasCatalogFilters(query) ? catalogFacets(db, effective) : Promise.resolve({ data: all }),
			]);
			if (
				family &&
				query.page === 1 &&
				!query.q &&
				!query.product &&
				!query.outcome &&
				!query.type &&
				!LEGACY_FILTER_KEYS.some((key) => query[key])
			)
				starter = await starterCollection(db, family);
		}
	} catch (err) {
		console.error(err);
		status = 503;
	}
	return { query, family, base, familyLabel, result, facets, registry, status, starter };
}
