// Feature-specific anonymous probes. All transport, bounds and header policy stay in smoke.mjs.
import assert from 'node:assert/strict';
import { elements, attr, text } from './markup.mjs';

const filters = [
	['categoryId', 'categories', 'Category', 'category'],
	['featureId', 'features', 'Feature', 'feature'],
	['domain', 'domains', 'Domain', 'domain'],
	['level', 'levels', 'Level', 'level'],
	['impact', 'impacts', 'Impact', 'impact'],
	['difficulty', 'difficulties', 'Difficulty', 'difficulty'],
];
const classification = (entry) => ({
	domain: entry.domain,
	categoryId: entry.category_id,
	category: entry.category_name,
	featureId: entry.feature_id,
	feature: entry.feature_name,
	level: entry.recommendation_level,
	impact: entry.impact_level,
	difficulty: entry.difficulty_level,
});
const unescapeMarkdown = (value) => value.replace(/\\([\\`*_{}\[\]<>()#+.!|~-])/g, '$1');

export async function verifyLegacyFilters({ request, publicResponse, document, legacyId }) {
	async function json(path) {
		const result = await request(path, { accept: 'application/json' });
		publicResponse(result, 'application/json');
		const body = JSON.parse(result.body);
		assert.equal(body.success, true);
		return body;
	}
	const legacy = (await json('/api/practices')).data;
	const sample = legacy.find((entry) => entry.practice_id === legacyId);
	assert.ok(sample, 'A published legacy sample is required');
	assert.equal(Object.hasOwn(sample, 'legacyClassification'), false, 'v1 must stay unchanged');
	const recorded = classification(sample);
	for (const [key, , , labelKey] of filters) {
		assert.ok(recorded[key] !== null && recorded[key] !== undefined && recorded[key] !== '', 'Sample needs all six recorded filters');
		assert.equal(typeof recorded[labelKey], 'string');
	}
	const detail = (await json(`/api/v2/entries/${legacyId}`)).data;
	assert.equal(detail.practiceId, legacyId);
	assert.equal(detail.schemaVersion, 0);
	assert.deepEqual(detail.legacyClassification, recorded);
	const registry = (await json('/api/v2/facets')).data.legacy;
	for (const [key, group, , labelKey] of filters) {
		assert.ok(Array.isArray(registry[group]) && registry[group].length > 0);
		assert.ok(registry[group].every((option) => typeof option.value === 'string' && Number.isInteger(option.count) && option.count > 0));
		assert.ok(registry[group].some((option) => option.value === String(recorded[key]) && option.label === recorded[labelKey]));
		// Independently check each SQL filter, not just one accidentally correlated conjunction.
		const single = await json(`/api/v2/entries?${new URLSearchParams({ [key]: recorded[key], pageSize: '1' })}`);
		assert.equal(single.query[key], String(recorded[key]));
		assert.equal(single.total, legacy.filter((entry) => classification(entry)[key] === recorded[key]).length);
	}
	const params = new URLSearchParams(filters.map(([key]) => [key, String(recorded[key])]));
	params.set('pageSize', '50');
	const effective = params.toString();
	const matches = legacy.filter((entry) => filters.every(([key]) => classification(entry)[key] === recorded[key]));
	const page = await json(`/api/v2/entries?${effective}`);
	assert.equal(page.total, matches.length);
	assert.equal(page.data.length, Math.min(matches.length, 50));
	const ids = page.data.map((entry) => entry.practiceId);
	assert.equal(new Set(ids).size, ids.length);
	for (const entry of page.data) {
		const original = matches.find((row) => row.practice_id === entry.practiceId);
		assert.ok(original, 'Only matching published legacy summaries may appear');
		assert.equal(entry.schemaVersion, 0);
		assert.deepEqual(entry.legacyClassification, classification(original));
		assert.equal(Object.hasOwn(entry, 'body'), false);
	}
	const facets = (await json(`/api/v2/facets?${effective}`)).data.legacy;
	for (const [key, group, , labelKey] of filters)
		assert.deepEqual(facets[group], [{ value: String(recorded[key]), label: recorded[labelKey], count: matches.length }]);
	const html = await document(`/catalog?${effective}`, 'text/html', 'text/html');
	const nodes = elements(html.body);
	assert.ok(nodes.some((n) => n.tagName === 'form' && attr(n, 'method') === 'get' && attr(n, 'action') === '/catalog'));
	assert.deepEqual(
		nodes
			.filter((n) => n.tagName === 'a' && /^\/practices\/\d+$/.test(attr(n, 'href') ?? ''))
			.map((n) => Number(attr(n, 'href').split('/').at(-1))),
		ids,
	);
	for (const [key] of filters) {
		const select = nodes.find((n) => n.tagName === 'select' && attr(n, 'name') === key);
		assert.ok(select);
		assert.ok(
			elements(select).some(
				(n) => n.tagName === 'option' && attr(n, 'value') === String(recorded[key]) && attr(n, 'selected') !== undefined,
			),
		);
	}
	const markdown = await document(`/catalog?${effective}`, 'text/markdown', 'text/markdown');
	const alias = await request(`/catalog.md?${effective}`, { accept: 'text/html' });
	publicResponse(alias, 'text/markdown');
	assert.equal(alias.body, markdown.body);
	assert.deepEqual(
		[...markdown.body.matchAll(/\/practices\/(\d+)\)/g)].map((match) => Number(match[1])),
		ids,
	);
	for (const [, , label, labelKey] of filters) assert.ok(unescapeMarkdown(markdown.body).includes(`${label}: ${recorded[labelKey]}`));

	const noisy = new URLSearchParams(params);
	noisy.set('categoryId', `000${recorded.categoryId}`);
	noisy.append('categoryId', '2147483647');
	noisy.set('page', '1');
	noisy.set('tracking', 'ignored');
	const normalized = await json(`/api/v2/entries?${noisy}`);
	assert.deepEqual(normalized, page);
	await document(`/catalog?${noisy}`, 'text/html', 'text/html', `/catalog?${effective}`);
	const baseline = await json('/api/v2/entries?pageSize=1');
	const invalid = await json(
		'/api/v2/entries?categoryId=invalid&categoryId=1&featureId=-1&domain=security&level=invalid&impact=invalid&difficulty=invalid&pageSize=1',
	);
	assert.deepEqual(invalid, baseline, 'Malformed first duplicates must disappear from SQL and normalized state');

	let unknown = 2147483647;
	const categories = new Set(legacy.map((entry) => entry.category_id));
	while (categories.has(unknown)) unknown--;
	const empty = new URLSearchParams(params);
	empty.set('categoryId', String(unknown));
	empty.delete('pageSize');
	empty.set('page', '2');
	empty.set('pageSize', '50');
	const emptyPage = await json(`/api/v2/entries?${empty}`);
	assert.equal(emptyPage.total, 0);
	assert.deepEqual(emptyPage.data, []);
	const emptyFacets = (await json(`/api/v2/facets?${empty}`)).data.legacy;
	for (const [, group] of filters) assert.deepEqual(emptyFacets[group], []);
	const emptyHtml = await document(`/catalog?${empty}`, 'text/html', 'text/html');
	const emptyNodes = elements(emptyHtml.body);
	for (const [key, , label] of filters) {
		const select = emptyNodes.find((n) => n.tagName === 'select' && attr(n, 'name') === key);
		assert.ok(select, 'Selected zero-result filters must remain in server HTML');
		assert.ok(
			elements(select).some((n) => n.tagName === 'option' && attr(n, 'selected') !== undefined && attr(n, 'value') === empty.get(key)),
		);
		const remove = emptyNodes.find((n) => n.tagName === 'a' && (attr(n, 'aria-label') ?? '').startsWith(`Remove ${label}:`));
		assert.ok(remove);
		assert.ok(text(remove).includes(label));
		const expected = new URLSearchParams(empty);
		expected.delete(key);
		expected.delete('page');
		assert.equal(attr(remove, 'href'), `/catalog?${expected}`);
	}
}
