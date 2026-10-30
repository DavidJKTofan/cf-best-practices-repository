// Explicit ephemeral pilot rehearsal. Never touches the ordinary dev DB or remote resources.
import { frontendHarness, seedFrontend, PILOT_IDS } from './test/helpers/frontend-harness.mjs';
import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { once } from 'node:events';

const server = frontendHarness();
let noScripts;
try {
	const { url } = await server.listen();
	const { DB } = await server.getWorker().getEnv();
	const starterCollection = process.argv.includes('--starters');
	await seedFrontend(DB, { starterCollection });
	console.log(`Ephemeral ${starterCollection ? 'Phase 5 starter' : 'Phase 3 pilot'} preview: ${url}`);
	console.log(`Test-only IDs: ${starterCollection ? '810001–810004' : PILOT_IDS.join(', ')}. Stop with Ctrl-C; data is not retained.`);
	if (process.argv.includes('--no-scripts')) {
		// Local-only browser rehearsal: CSP disables every page script, including enhancements.
		noScripts = createServer(async (request, response) => {
			try {
				if (!['GET', 'HEAD'].includes(request.method)) {
					response.writeHead(405).end();
					return;
				}
				const upstream = await server.fetch(request.url, { method: request.method, headers: { Accept: request.headers.accept ?? '*/*' } });
				response.writeHead(upstream.status, {
					...Object.fromEntries(upstream.headers),
					'Content-Security-Policy': "script-src 'none'; object-src 'none'; base-uri 'self'",
				});
				if (upstream.body) Readable.fromWeb(upstream.body).pipe(response);
				else response.end();
			} catch (err) {
				console.error(err);
				response.destroy(err);
			}
		}).listen(0, '127.0.0.1');
		await once(noScripts, 'listening');
		console.log(`Scripts blocked by CSP: http://127.0.0.1:${noScripts.address().port}/`);
	}
} catch (err) {
	console.error(err);
	await server.close();
	process.exitCode = 1;
}
for (const signal of ['SIGINT', 'SIGTERM'])
	process.once(signal, async () => {
		noScripts?.close();
		await server.close();
		process.exit(0);
	});
