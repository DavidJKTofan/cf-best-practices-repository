import type { catalogFacets } from './v2-queries';
import type { CatalogQuery } from './v2-filters';
import { CATALOG_FILTER_KEYS } from './v2-filters';
import { TYPE_LABELS } from '../../content/presentation';

type Facets = Awaited<ReturnType<typeof catalogFacets>>['data'];
export const PRACTICE_FILTER_GROUPS = [
	{ key: 'categoryId', group: 'categories', label: 'Category', empty: 'All categories' },
	{ key: 'featureId', group: 'features', label: 'Feature', empty: 'All features' },
	{ key: 'domain', group: 'domains', label: 'Domain', empty: 'All domains' },
	{ key: 'level', group: 'levels', label: 'Level', empty: 'All levels' },
	{ key: 'impact', group: 'impacts', label: 'Impact', empty: 'Any impact' },
	{ key: 'difficulty', group: 'difficulties', label: 'Difficulty', empty: 'Any difficulty' },
] as const;

export function activeFilters(query: CatalogQuery, registry: Facets, familyLocked = false) {
	return CATALOG_FILTER_KEYS.filter((key) => query[key] && !(key === 'family' && familyLocked)).map((key) => {
		const practice = PRACTICE_FILTER_GROUPS.find((group) => group.key === key);
		if (practice) {
			const value = registry.legacy[practice.group].find((option) => option.value === query[key])?.label ?? query[key];
			return { key, label: `${practice.label}: ${value}` };
		}
		const labels = { q: 'Search', family: 'Family', product: 'Product', outcome: 'Outcome', type: 'Type' };
		let value = query[key];
		if (key === 'type') value = TYPE_LABELS[value] ?? value;
		for (const [filter, group] of [
			['family', 'families'],
			['product', 'products'],
			['outcome', 'outcomes'],
		] as const)
			if (key === filter) value = registry[group].find((option) => option.slug === value)?.label ?? value;
		return { key, label: `${labels[key as keyof typeof labels] ?? key}: ${value}` };
	});
}
