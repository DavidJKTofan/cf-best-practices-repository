import assert from 'node:assert/strict';
import { test } from 'node:test';
import { frontendHarness, seedFrontend } from './helpers/frontend-harness.mjs';
import { runSmoke } from '../release/smoke.mjs';

test('release HTTP probes exercise the actual built Worker and refuse to certify local Access/cache', { timeout: 60_000 }, async () => {
	const server = frontendHarness();
	try {
		await server.listen();
		const { DB } = await server.getWorker().getEnv();
		await seedFrontend(DB, { starterCollection: true });
		const entry = (await (await server.fetch('/api/v2/entries/810002')).json()).data;
		const result = await runSmoke({
			base: 'https://db.automatic-demo.com',
			nativeId: entry.practiceId,
			expectedRevision: entry.revisionId,
			expectCacheHits: true,
			fetcher: (target, init) => {
				const url = new URL(target);
				return server.fetch(url.pathname + url.search, init);
			},
		});
		assert.equal(result.ok, false, 'Local success must not imply live readiness');
		assert.deepEqual(
			result.checks.filter((c) => !c.ok).map((c) => c.name),
			['anonymous-private-route-denial', 'live-independent-html-markdown-hits'],
		);
	} finally {
		await server.close();
	}
});
