import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createEditorialSubmission } from '../../public/editorial-retry.js';

const path = '/dashboard/api/catalog';
const body = '{"content":"PRIVATE_CONTENT_CANARY"}';
function storage() {
	const values = new Map();
	return {
		getItem: (key) => values.get(key),
		setItem: (key, value) => values.set(key, value),
		removeItem: (key) => values.delete(key),
		values,
	};
}
test('editorial retry keeps the exact operation key across uncertain responses and reloads without persisting content', async () => {
	const tab = storage();
	const one = createEditorialSubmission(tab);
	const key = await one.key(path, 'POST', body, () => {
		throw new Error('Unchanged retries must not ask for a new key');
	});
	assert.equal(await one.key(path, 'POST', body), key);
	assert.equal(await createEditorialSubmission(tab).key(path, 'POST', body), key);
	assert.ok(!JSON.stringify([...tab.values]).includes('PRIVATE_CONTENT_CANARY'));
	one.complete();
	assert.equal(tab.values.size, 0);
	assert.notEqual(await one.key(path, 'POST', body), key);
});
test('changing an unresolved payload, target or method cannot silently rotate the editorial key', async () => {
	const one = createEditorialSubmission(storage());
	const key = await one.key(path, 'POST', body);
	for (const [target, method, data] of [
		[path, 'POST', '{}'],
		[path + '/1/draft', 'PUT', body],
		[path, 'GET', body],
	])
		assert.equal(await one.key(target, method, data, () => false), null);
	assert.equal(await one.key(path, 'POST', body), key);
	assert.notEqual(await one.key(path, 'POST', '{}', () => true), key);
});
test('denied/corrupt storage preserves in-memory retry protection', async () => {
	for (const tab of [
		undefined,
		{
			getItem() {
				throw new Error('denied');
			},
			setItem() {
				throw new Error('denied');
			},
			removeItem() {
				throw new Error('denied');
			},
		},
		{ ...storage(), getItem: () => 'bad json' },
	]) {
		const one = createEditorialSubmission(tab);
		const key = await one.key(path, 'POST', body);
		assert.equal(await one.key(path, 'POST', body), key);
		one.complete();
		assert.notEqual(await one.key(path, 'POST', body), key);
	}
});
