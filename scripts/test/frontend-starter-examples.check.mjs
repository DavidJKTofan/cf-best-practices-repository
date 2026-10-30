import assert from 'node:assert/strict';
import { test, before, after } from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import ts from 'typescript';
import wrangler from 'wrangler';
import { starters } from './helpers/frontend-harness.mjs';

let directory, server, db, repository;
const artifacts = starters.find((entry) => entry.id === 810003).content.body.artifacts;
before(
	async () => {
		directory = await mkdtemp(join(tmpdir(), 'cf-phase5-example-'));
		const source = artifacts.find((a) => a.filename === 'summaries.ts').code;
		const path = join(directory, 'summaries.ts');
		await writeFile(path, source);
		const program = ts.createProgram([path, resolve('worker-configuration.d.ts')], {
			target: ts.ScriptTarget.ES2024,
			module: ts.ModuleKind.ES2022,
			moduleResolution: ts.ModuleResolutionKind.Bundler,
			lib: ['lib.es2024.d.ts'],
			types: [],
			strict: true,
			skipLibCheck: true,
			noEmit: true,
		});
		const errors = ts.getPreEmitDiagnostics(program).filter((d) => d.category === ts.DiagnosticCategory.Error);
		assert.equal(errors.length, 0, errors.map((error) => ts.flattenDiagnosticMessageText(error.messageText, '\n')).join('\n'));
		await writeFile(
			join(directory, 'summaries.mjs'),
			ts.transpileModule(source, {
				compilerOptions: { target: ts.ScriptTarget.ES2024, module: ts.ModuleKind.ES2022 },
			}).outputText,
		);
		await writeFile(
			join(directory, 'worker.mjs'),
			`import { WorkerEntrypoint } from 'cloudflare:workers';
import { listSummaries } from './summaries.mjs';
export default class extends WorkerEntrypoint {
  list(after, limit) { return listSummaries(this.env.DB, after, limit); }
}`,
		);
		server = wrangler.createTestHarness({
			workers: [
				{
					config: {
						name: 'phase5-example-only',
						main: join(directory, 'worker.mjs'),
						compatibility_date: '2026-10-01',
						compatibility_flags: ['nodejs_compat'],
						d1_databases: [{ binding: 'DB', database_name: 'phase5-example-only', database_id: '00000000-0000-0000-0000-000000000000' }],
					},
				},
			],
		});
		await server.listen();
		({ DB: db } = await server.getWorker().getEnv());
		await db.batch(wrangler.unstable_splitSqlQuery(artifacts.find((a) => a.filename === 'schema.sql').code).map((sql) => db.prepare(sql)));
		for (let id = 1; id <= 103; id++)
			await db
				.prepare('INSERT INTO Articles (id, title, body, published) VALUES (?, ?, ?, ?)')
				.bind(id, `Article ${id}`, 'LARGE_PRIVATE_BODY_CANARY'.repeat(1000), id % 2)
				.run();
		repository = await server.getWorker().getExport();
	},
	{ timeout: 60_000 },
);
after(async () => {
	await server?.close();
	if (directory) await rm(directory, { recursive: true, force: true });
});

test('displayed summary TypeScript/SQL typecheck and bound real D1 pages without body/unpublished leaks', async () => {
	for (const limit of [1, 50]) {
		let after = 0;
		const seen = [];
		for (;;) {
			const page = await repository.list(after, limit);
			assert.ok(page.length <= limit);
			if (!page.length) break;
			for (const row of page) {
				assert.deepEqual(Object.keys(row).sort(), ['id', 'title']);
				assert.equal(row.id % 2, 1);
				seen.push(row.id);
			}
			after = page.at(-1).id;
		}
		assert.deepEqual(
			seen,
			Array.from({ length: 52 }, (_, index) => index * 2 + 1),
		);
	}
	for (const [after, limit] of [
		[-1, 1],
		[1.5, 1],
		[Number.MAX_SAFE_INTEGER + 1, 1],
		[0, 0],
		[0, 51],
		[0, 1.5],
	])
		await assert.rejects(async () => await repository.list(after, limit), /Invalid cursor or page size/);
	const plan = await db
		.prepare('EXPLAIN QUERY PLAN SELECT id, title FROM Articles WHERE published = 1 AND id > ? ORDER BY id LIMIT ?')
		.bind(0, 50)
		.all();
	assert.ok(plan.results.some((row) => row.detail.includes('articles_published_id')));
});

test('displayed keyset pagination documents live membership, not an invented frozen snapshot', async () => {
	await db.prepare("INSERT INTO Articles (id, title, body, published) VALUES (104, 'New', 'Private body', 1)").run();
	assert.deepEqual(await repository.list(103, 10), [{ id: 104, title: 'New' }]);
	await db.prepare('UPDATE Articles SET published = 0 WHERE id = 104').run();
	assert.deepEqual(await repository.list(103, 10), []);
});
