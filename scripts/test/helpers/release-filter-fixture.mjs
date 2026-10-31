// Synthetic public responses only; this helper never contacts a host or imports app queries.
const filters = [
	['categoryId', 'category_id', 'categories', 'Category', 'category_name', 2],
	['featureId', 'feature_id', 'features', 'Feature', 'feature_name', 2],
	['domain', 'domain', 'domains', 'Domain', 'domain', 'General'],
	['level', 'recommendation_level', 'levels', 'Level', 'recommendation_level', 'Situational'],
	['impact', 'impact_level', 'impacts', 'Impact', 'impact_level', 'Medium'],
	['difficulty', 'difficulty_level', 'difficulties', 'Difficulty', 'difficulty_level', 'Complex'],
];
const sample = {
	practice_id: 18,
	title: 'Fixture & policy',
	domain: 'Security',
	category_id: 1,
	category_name: 'WAF _custom_ rules',
	feature_id: 1,
	feature_name: 'WAF',
	recommendation_level: 'Recommended',
	impact_level: 'High',
	difficulty_level: 'Easy',
};
const legacy = [
	sample,
	...filters.map(([, field, , , labelField, other], index) => ({
		...sample,
		practice_id: 19 + index,
		[field]: other,
		...(field !== labelField ? { [labelField]: 'Other recorded label' } : {}),
	})),
];
const classification = (row) =>
	Object.fromEntries(
		filters.flatMap(([key, field, , , labelField]) => [
			[key, row[field]],
			...(key === 'categoryId' ? [['category', row[labelField]]] : key === 'featureId' ? [['feature', row[labelField]]] : []),
		]),
	);
const summary = (row) => ({ practiceId: row.practice_id, schemaVersion: 0, legacyClassification: classification(row) });
const escape = (value) =>
	String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const markdown = (value) => String(value).replace(/([\\`*_{}\[\]<>()#+.!|~-])/g, '\\$1');

export function filterFixture(fallback) {
	return async (target, init) => {
		const original = await fallback(target, init);
		if (init.method === 'OPTIONS') return original;
		const url = new URL(target);
		const path = url.pathname;
		if (!['/api/practices', '/api/v2/entries/18', '/api/v2/entries', '/api/v2/facets', '/catalog', '/catalog.md'].includes(path))
			return original;
		const p = url.searchParams;
		const query = {};
		for (const [key, field] of filters) {
			const value = p.get(key) ?? '';
			query[key] = key.endsWith('Id')
				? /^\d+$/.test(value) && Number(value) > 0 && Number(value) <= 2147483647
					? String(Number(value))
					: ''
				: legacy.some((row) => row[field] === value)
					? value
					: '';
		}
		query.page = Number(p.get('page')) || 1;
		query.pageSize = Math.min(Number(p.get('pageSize')) || 20, 50);
		const state = new URLSearchParams(filters.filter(([key]) => query[key]).map(([key]) => [key, query[key]]));
		if (query.page !== 1) state.set('page', String(query.page));
		if (query.pageSize !== 20) state.set('pageSize', String(query.pageSize));
		const canonicalPath = `/catalog${state.size ? `?${state}` : ''}`;
		const matches = legacy.filter((row) => filters.every(([key, field]) => !query[key] || String(row[field]) === query[key]));
		const rows = matches.slice((query.page - 1) * query.pageSize, query.page * query.pageSize);
		const headers = new Headers(original.headers);
		let body;
		if (path.startsWith('/api/')) {
			headers.set('Content-Type', 'application/json');
			headers.set('X-Robots-Tag', 'noindex');
			const data =
				path === '/api/practices'
					? legacy
					: path === '/api/v2/entries/18'
						? summary(sample)
						: path === '/api/v2/facets'
							? {
									legacy: Object.fromEntries(
										filters.map(([, field, group, , labelField]) => [
											group,
											[...new Set(matches.map((row) => row[field]))].map((value) => ({
												value: String(value),
												label: matches.find((row) => row[field] === value)[labelField],
												count: matches.filter((row) => row[field] === value).length,
											})),
										]),
									),
								}
							: rows.map(summary);
			body = JSON.stringify({
				success: true,
				data,
				...(path === '/api/v2/entries'
					? { total: matches.length, query, links: { self: `/api/v2/entries${state.size ? `?${state}` : ''}` } }
					: {}),
			});
		} else {
			const md =
				path.endsWith('.md') || (init.headers.Accept.includes('text/markdown') && !init.headers.Accept.includes('text/markdown;q=0'));
			headers.set('Content-Type', md ? 'text/markdown' : 'text/html');
			headers.set('Link', `<${url.origin}${canonicalPath}>; rel="canonical"`);
			headers.set('Vary', 'Accept');
			body = md
				? `Canonical URL: ${url.origin}${canonicalPath}\n\n${rows.map((row) => `- [${markdown(row.title)}](${url.origin}/practices/${row.practice_id})\n  ${filters.map(([, , , label, field]) => markdown(`${label}: ${row[field]}`)).join(' · ')}`).join('\n')}`
				: `<html><head><link rel="canonical" href="${escape(url.origin + canonicalPath)}"></head><body><form method="get" action="/catalog">${filters.map(([key]) => `<select name="${key}"><option value="${escape(query[key])}" selected>${escape(query[key])}</option></select>`).join('')}</form>${rows.map((row) => `<article><a href="/practices/${row.practice_id}">${escape(row.title)}</a></article>`).join('')}${filters
						.filter(([key]) => query[key])
						.map(([key, , , label]) => {
							const cleared = new URLSearchParams(state);
							cleared.delete(key);
							cleared.delete('page');
							return `<a aria-label="Remove ${label}: ${escape(query[key])}" href="/catalog?${escape(cleared)}">${label}</a>`;
						})
						.join('')}</body></html>`;
		}
		return new Response(init.method === 'HEAD' ? null : body, { headers });
	};
}
