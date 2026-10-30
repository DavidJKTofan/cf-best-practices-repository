import assert from 'node:assert/strict';
import { test, before, after } from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import ts from 'typescript';
import wrangler from 'wrangler';
import { pilots } from './helpers/frontend-harness.mjs';

let directory, server, db, repository;
const artifacts = pilots.find((p) => p.type === 'implementation-guide').body.artifacts;
before(
	async () => {
		directory = await mkdtemp(join(tmpdir(), 'cf-field-guide-pilot-'));
		const source = artifacts.find((a) => a.filename === 'repository.ts').code;
		const path = join(directory, 'repository.ts');
		await writeFile(path, source);
		// Typecheck the actual displayed example against the project's generated platform types.
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
		assert.equal(
			errors.length,
			0,
			ts.formatDiagnosticsWithColorAndContext(errors, {
				getCanonicalFileName: (f) => f,
				getCurrentDirectory: () => process.cwd(),
				getNewLine: () => '\n',
			}),
		);
		// Compile only in this isolated test. The application never executes stored code.
		const compiled = ts.transpileModule(source, {
			compilerOptions: { target: ts.ScriptTarget.ES2024, module: ts.ModuleKind.ES2022 },
		}).outputText;
		await writeFile(join(directory, 'repository.mjs'), compiled);
		await writeFile(
			join(directory, 'worker.mjs'),
			`import { WorkerEntrypoint } from 'cloudflare:workers';
import { createItem } from './repository.mjs';
export default class extends WorkerEntrypoint {
  create(actor, key, value) { return createItem(this.env.DB, actor, key, value); }
}`,
		);
		server = wrangler.createTestHarness({
			workers: [
				{
					config: {
						name: 'phase3-code-fixture',
						main: join(directory, 'worker.mjs'),
						compatibility_date: '2026-10-01',
						compatibility_flags: ['nodejs_compat'],
						d1_databases: [{ binding: 'DB', database_name: 'phase3-example-only', database_id: '00000000-0000-0000-0000-000000000000' }],
					},
				},
			],
		});
		await server.listen();
		({ DB: db } = await server.getWorker().getEnv());
		const schema = artifacts.find((a) => a.filename === 'schema.sql').code;
		await db.batch(wrangler.unstable_splitSqlQuery(schema).map((sql) => db.prepare(sql)));
		repository = await server.getWorker().getExport();
	},
	{ timeout: 60_000 },
);
after(async () => {
	await server?.close();
	if (directory) await rm(directory, { recursive: true, force: true });
});

test('displayed D1 example typechecks and recovers unchanged retries, actor scope, and a lost response', async () => {
	const id = await repository.create('actor-a', 'fixture-key', 'value');
	assert.equal(await repository.create('actor-a', 'fixture-key', 'value'), id);
	await assert.rejects(async () => await repository.create('actor-a', 'fixture-key', 'changed'), /Key already used for different data/);
	assert.notEqual(await repository.create('actor-b', 'fixture-key', 'value'), id);
	// Deliberately discard the first result, as a client would after a lost response.
	await repository.create('actor-a', 'lost-response', 'value');
	const replay = await repository.create('actor-a', 'lost-response', 'value');
	const saved = await db.prepare("SELECT item_id FROM ItemReceipts WHERE actor = 'actor-a' AND key = 'lost-response'").first();
	assert.equal(replay, saved.item_id);
});

test('displayed D1 example resolves concurrent same-key attempts to one item and rolls back receipt failures', async () => {
	const before = (await db.prepare('SELECT COUNT(*) AS n FROM Items').first()).n;
	const ids = await Promise.all(Array.from({ length: 6 }, () => repository.create('actor-c', 'concurrent', 'value')));
	assert.equal(new Set(ids).size, 1);
	assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM Items').first()).n, before + 1);
	await db
		.prepare(
			"CREATE TRIGGER RefuseFixtureReceipt BEFORE INSERT ON ItemReceipts WHEN NEW.key = 'rollback' BEGIN SELECT RAISE(ABORT, 'forced receipt failure'); END",
		)
		.run();
	await assert.rejects(async () => await repository.create('actor-c', 'rollback', 'value'), /forced receipt failure/);
	assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM Items').first()).n, before + 1);
});
