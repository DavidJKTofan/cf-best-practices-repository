import { catalogQuery, catalogSearch } from './v2-filters';

export function isCatalogListing(path: string): boolean {
	if (/^\/catalog(?:\.md)?$/.test(path)) return true;
	const family = /^\/families\/([a-z0-9]+(?:-[a-z0-9]+)*)(?:\.md)?$/.exec(path)?.[1];
	return !!family && family.length <= 80;
}
export function listingState(url: URL) {
	const copy = new URL(url);
	const family = /^\/families\/([^/.]+)/.exec(copy.pathname)?.[1];
	if (family) copy.searchParams.set('family', family);
	return catalogQuery(copy);
}
export function listingSearch(url: URL): string {
	const state = listingState(url);
	const params = new URLSearchParams(catalogSearch(state));
	if (url.pathname.startsWith('/families/')) params.delete('family');
	return params.toString();
}
export function documentPath(url: URL): string {
	const search = isCatalogListing(url.pathname) ? listingSearch(url) : '';
	return `${url.pathname.replace(/\.md$/, '')}${search ? `?${search}` : ''}`;
}
export function markdownPath(url: URL): string {
	if (url.pathname === '/') return '/index.md';
	const path = documentPath(url);
	const index = path.indexOf('?');
	return index < 0 ? `${path}.md` : `${path.slice(0, index)}.md${path.slice(index)}`;
}
