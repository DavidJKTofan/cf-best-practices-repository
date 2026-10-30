import assert from 'node:assert/strict';
import { before, after, test } from 'node:test';
import { parse } from 'parse5';
import { frontendHarness, seedFrontend, pilots, PILOT_IDS, storePilot } from './helpers/frontend-harness.mjs';

let server, db;
before(
	async () => {
		server = frontendHarness();
		await server.listen();
		({ DB: db } = await server.getWorker().getEnv());
		await seedFrontend(db);
	},
	{ timeout: 60_000 },
);
after(async () => {
	await server?.close();
});

const read = async (path, init) => {
	const response = await server.fetch(path, init);
	return { response, text: await response.text() };
};
const unescapeMarkdown = (text) => text.replace(/\\([\\`*_{}\[\]<>()#+.!|~-])/g, '$1');

test('Astro homepage is SSR through PublicReads, retains legacy fragments, and never loads the full-body client', async () => {
	const { response, text } = await read('/?q=ignored');
	assert.equal(response.status, 200);
	assert.match(text, /<h1>Cloudflare recommendations (?:&amp;|&) patterns<\/h1>/);
	assert.match(text, /id="practice-18"/);
	assert.match(text, /href="\/practices\/18"/);
	assert.match(text, /href="\/families\/cloudflare-one"/);
	assert.ok(!text.includes('href="/families/network-services"'));
	assert.ok(!text.includes('src="/app.js"'));
	assert.ok(!text.includes('last_insert_rowid()'), 'body snippets must not be downloaded on homepage');
	assert.equal(response.headers.get('Cache-Tag'), 'practices');
	assert.equal(response.headers.get('Vary'), 'Accept');
	assert.equal(response.headers.get('Set-Cookie'), null);
	assert.equal(response.headers.get('ETag'), null);
	assert.equal(response.headers.get('X-Robots-Tag'), null);
});

test('GET forms, active filters, pagination and canonical/Markdown links preserve effective URL state', async () => {
	const { response, text } = await read('/catalog?q=origin&pageSize=1&page=1&sort=title&utm_source=ignored');
	assert.equal(response.status, 200);
	assert.match(text, /method="get" action="\/catalog"/);
	assert.match(text, /value="origin"/);
	assert.match(text, /canonical" href="https:\/\/db\.automatic-demo\.com\/catalog\?q=origin(?:&amp;|&)pageSize=1"/);
	assert.ok(!response.headers.get('Link').includes('utm_source'));
	assert.match(response.headers.get('Link'), /catalog\.md\?q=origin&pageSize=1/);
	const md = await read('/catalog.md?q=origin&pageSize=1', { headers: { Accept: 'text/html' } });
	assert.match(md.response.headers.get('Content-Type'), /text\/markdown/);
	assert.match(md.text, /matching entries/);
	const page = await read('/catalog?pageSize=1');
	assert.match(page.text, /rel="next" href="\/catalog\?page=2(?:&amp;|&)pageSize=1"/);
});

test('family journeys lock the family, hide empty hubs, and return useful empty/error states', async () => {
	const hub = await read('/families/cloudflare-one?family=application-services');
	assert.equal(hub.response.status, 200);
	assert.match(hub.text, /Browser access to a private origin/);
	assert.ok(!hub.text.includes(pilots[0].title));
	assert.equal((await read('/families/network-services')).response.status, 404);
	const empty = await read('/catalog?q=NO_SUCH_PATTERN');
	assert.equal(empty.response.status, 200);
	assert.match(empty.text, /No matching guidance/);
	const missing = await read('/practices/2147483647');
	assert.equal(missing.response.status, 404);
	assert.equal(missing.response.headers.get('Cache-Control'), 'no-store');
	assert.equal(missing.response.headers.get('X-Robots-Tag'), 'noindex');
});

test('catalog pagination is bounded, complete, summary-only and progressively enhanced without changing GET forms', async () => {
	const ids = new Set();
	let path = '/api/v2/entries?pageSize=10',
		total;
	while (path) {
		const page = await (await server.fetch(path)).json();
		total ??= page.total;
		assert.equal(page.total, total);
		assert.ok(page.data.length <= 10);
		for (const row of page.data) {
			assert.ok(!ids.has(row.practiceId), 'No duplicate entry across stable pages');
			assert.ok(!('body' in row) && !('expression' in row) && !('applicability' in row));
			ids.add(row.practiceId);
		}
		path = page.links.next;
	}
	assert.equal(ids.size, total);
	const clamped = await (await server.fetch('/api/v2/entries?pageSize=999')).json();
	assert.equal(clamped.pageSize, 50);
	assert.equal(clamped.data.length, 50);
	const { text } = await read('/catalog?page=2&pageSize=10');
	assert.match(text, /src="\/catalog-search\.js"/);
	assert.match(text, /data-catalog-view/);
	assert.match(text, /data-catalog-results/);
	assert.match(text, /method="get" action="\/catalog"/);
	assert.ok(!text.includes('name="page"'), 'Changing filters resets pagination');
});

test('all three typed pilots have complete same-revision HTML, Markdown, JSON and semantic reading sections', async () => {
	for (const [i, pilot] of pilots.entries()) {
		const id = PILOT_IDS[i];
		const html = await read(`/practices/${id}`);
		const md = await read(`/practices/${id}.md`, { headers: { Accept: 'text/html' } });
		const json = await (await server.fetch(`/api/v2/entries/${id}`)).json();
		assert.equal(html.response.status, 200, html.text);
		assert.equal(md.response.status, 200);
		assert.equal(json.data.canonicalPath, `/practices/${id}`);
		assert.equal(json.data.v1Eligible, false);
		assert.equal(json.data.title, pilot.title);
		assert.match(html.text, /id="validation"/);
		assert.match(html.text, /id="rollback"/);
		assert.match(html.text, /id="sources"/);
		for (const source of pilot.sources) assert.ok(html.text.includes(source.url.replace(/&/g, '&amp;')) && md.text.includes(source.url));
		for (const item of pilot.body.validation)
			assert.ok(html.text.includes(item.replace(/&/g, '&amp;').replace(/</g, '&lt;')) && unescapeMarkdown(md.text).includes(item));
		assert.ok(html.text.includes(`Revision ${json.data.revisionId}`));
		assert.ok(md.text.includes(`Revision: ${json.data.revisionId}`));
		assert.ok(html.text.includes(pilot.factVerifiedAt));
		if (pilot.type === 'reference-architecture') assert.ok(unescapeMarkdown(md.text).includes(pilot.body.diagramText));
		if (pilot.type === 'implementation-guide')
			for (const block of pilot.body.artifacts.filter((b) => b.kind === 'code')) assert.ok(md.text.includes(block.code));
	}
});

test('all legacy links still render the unchanged v1 content, and practice 18 keeps separate match conditions', async () => {
	const { data } = await (await server.fetch('/api/practices')).json();
	assert.equal(data.length, 119);
	for (const row of data) {
		const { response, text } = await read(`/practices/${row.practice_id}`);
		assert.equal(response.status, 200);
		assert.ok(text.includes(row.title.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')), row.title);
		assert.equal(text.includes('id="expression"'), Boolean(row.expression?.trim()), row.title);
		assert.equal(
			text.includes('id="configuration"'),
			Boolean(row.expressions_configuration_details?.trim() && row.expressions_configuration_details !== row.expression),
			row.title,
		);
		const nodes = elements(parse(text));
		const ids = new Set(nodes.map((node) => attr(node, 'id')).filter(Boolean));
		for (const node of nodes.filter((node) => node.tagName === 'a' && attr(node, 'href')?.startsWith('#'))) {
			assert.ok(ids.has(attr(node, 'href').slice(1)), `Missing contents target on ${row.practice_id}`);
		}
	}
	const p = data.find((p) => p.practice_id === 18);
	const html = (await read('/practices/18')).text;
	const md = unescapeMarkdown((await read('/practices/18.md')).text);
	assert.ok(html.includes('data-copy-kind="expression"'));
	assert.ok(html.includes('Enterprise'));
	assert.ok(md.includes(p.expression));
	assert.ok(md.includes(p.notes));
});

const attr = (node, name) => node.attrs?.find((a) => a.name === name)?.value;
const elements = (node) => [node, ...(node.childNodes ?? []).flatMap(elements)];

test('legacy reading sections and contents omit absent fields without duplicating headings or expression text', async () => {
	const original = await db.prepare('SELECT * FROM BestPractices WHERE practice_id = 1').first();
	const update = (expression, configuration, notes, prerequisites) =>
		db
			.prepare(
				'UPDATE BestPractices SET expression = ?, expressions_configuration_details = ?, notes = ?, prerequisites = ? WHERE practice_id = 1',
			)
			.bind(expression, configuration, notes, prerequisites)
			.run();
	try {
		for (const [expression, configuration] of [
			[null, null],
			['', ''],
			[' \n ', '\t '],
			['(http.host eq "example.com")', null],
			[null, 'Configure an action separately.'],
			['same expression', 'same expression'],
			['match conditions', 'action guidance'],
		]) {
			await update(expression, configuration, '  ', '\n');
			const { response, text } = await read('/practices/1');
			assert.equal(response.status, 200);
			const nodes = elements(parse(text));
			for (const [kind, populated] of [
				['expression', Boolean(expression?.trim())],
				['configuration', Boolean(configuration?.trim() && configuration !== expression)],
			]) {
				assert.equal(nodes.filter((n) => attr(n, 'id') === kind).length, populated ? 1 : 0);
				assert.equal(nodes.filter((n) => n.tagName === 'a' && attr(n, 'href') === `#${kind}`).length, populated ? 1 : 0);
				assert.equal(nodes.filter((n) => attr(n, 'data-copy-kind') === kind).length, populated ? 1 : 0);
			}
			assert.ok(!nodes.some((n) => ['notes', 'related'].includes(attr(n, 'id'))));
			assert.ok(!text.includes('href="#related"') && !text.includes('href="#notes"'));
			assert.ok(!text.includes('<h2>Configuration</h2>') && !text.includes('<h3>Prerequisites</h3>'));
			const md = (await read('/practices/1.md')).text;
			assert.equal(md.includes('## Example expression'), Boolean(expression?.trim()));
			assert.equal(md.includes('## Configuration guidance'), Boolean(configuration?.trim() && configuration !== expression));
		}
	} finally {
		await update(original.expression, original.expressions_configuration_details, original.notes, original.prerequisites);
	}
});

test('unpopulated journeys and filter groups are absent, but selected zero-result filters remain clearable', async () => {
	const { results: entries } = await db
		.prepare('SELECT practice_id, published_revision_id FROM CatalogEntries WHERE published_revision_id IS NOT NULL')
		.all();
	try {
		await db.prepare('UPDATE CatalogEntries SET published_revision_id = NULL WHERE published_revision_id IS NOT NULL').run();
		const home = (await read('/')).text;
		assert.ok(!home.includes('class="journeys"') && !home.includes('Browse by family') && !home.includes('Browse by outcome'));
		assert.match(home, /Recently updated/);
		const catalog = (await read('/catalog')).text;
		assert.ok(!/name="(?:family|product|outcome)"/.test(catalog));
		assert.match(catalog, /name="type"/);
		const selected = (await read('/catalog?family=network-services')).text;
		assert.match(selected, /name="family"/);
		assert.match(selected, /value="network-services" selected/);
		assert.match(selected, /network-services \(0\)/);
		assert.match(selected, /Clear filters/);
		assert.ok(!selected.includes('class="pagination"'));
	} finally {
		await db.batch(
			entries.map((e) =>
				db
					.prepare('UPDATE CatalogEntries SET published_revision_id = ? WHERE practice_id = ?')
					.bind(e.published_revision_id, e.practice_id),
			),
		);
	}
});

test('empty optional typed sections have neither headings nor contents links in HTML or Markdown', async () => {
	const content = structuredClone(pilots[0]);
	content.applicability.excludes = [];
	content.applicability.dependencies = [];
	await storePilot(db, 800007, content);
	const html = (await read('/practices/800007')).text;
	assert.ok(!html.includes('id="exclusions"') && !html.includes('href="#exclusions"'));
	assert.ok(!html.includes('id="dependencies"') && !html.includes('href="#dependencies"'));
	const md = (await read('/practices/800007.md')).text;
	assert.ok(!md.includes('## Not for') && !md.includes('## Dependencies and availability'));
});

test('built v1 searches match full long literals and preserve empty results, HEAD and cache headers', async () => {
	const { data } = await (await server.fetch('/api/practices')).json();
	const row = data.find((p) => p.description.length >= 200);
	assert.ok(row, 'the real seed must exercise a complete 200-character search');
	const needle = row.description.slice(0, 200);
	for (const search of [needle, `${needle}ignored suffix`, '界'.repeat(200), '%_\\'.repeat(60)]) {
		const path = `/api/practices?search=${encodeURIComponent(search)}`;
		const response = await server.fetch(path);
		assert.equal(response.status, 200);
		assert.equal(response.headers.get('Cache-Tag'), 'practices');
		assert.match(response.headers.get('Cache-Control'), /max-age=60/);
		assert.equal(response.headers.get('Access-Control-Allow-Origin'), '*');
		const body = await response.json();
		assert.equal(body.success, true);
		assert.equal(body.count, body.data.length);
		if (search.startsWith(needle)) assert.ok(body.data.some((p) => p.practice_id === row.practice_id));
		else assert.deepEqual(body.data, []);
		const head = await server.fetch(path, { method: 'HEAD' });
		assert.equal(head.status, 200);
		assert.equal(head.headers.get('Cache-Tag'), 'practices');
		assert.equal(await head.text(), '');
	}
});

test('negotiation, HEAD, preflight and write prohibitions survive the built entrypoint', async () => {
	for (const path of ['/catalog?q=origin', '/families/cloudflare-one', `/practices/${PILOT_IDS[1]}`]) {
		const md = await read(path, { headers: { Accept: 'text/html;q=.2,text/markdown;q=1' } });
		assert.match(md.response.headers.get('Content-Type'), /text\/markdown/);
		assert.equal(md.response.headers.get('Vary'), 'Accept');
		assert.match((await read(path, { headers: { Accept: 'text/markdown;q=0,*/*' } })).response.headers.get('Content-Type'), /text\/html/);
		const head = await read(path, { method: 'HEAD' });
		assert.equal(head.response.status, 200);
		assert.equal(head.text, '');
		assert.equal((await server.fetch(path, { method: 'OPTIONS' })).status, 204);
		assert.equal((await server.fetch(path, { method: 'POST' })).status, 405);
	}
	assert.equal(
		(await server.fetch('/dashboard/api/practices', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }))
			.status,
		401,
	);
});

test('every discovery/export path includes published pilots and excludes drafts and unselected revisions', async () => {
	for (const path of [
		'/',
		'/catalog',
		'/catalog.md',
		'/families/application-services',
		'/api/v2/entries',
		'/api/v2/facets',
		'/llms.txt',
		'/sitemap.xml',
		'/index.md',
		'/llms-full.txt',
		`/practices/${PILOT_IDS[0]}`,
		`/practices/${PILOT_IDS[0]}.md`,
	]) {
		const { response, text } = await read(`${path}?draft=true&preview=true`);
		assert.equal(response.status, 200, path);
		assert.ok(!/PRIVATE_.*CANARY|private-canary/.test(text), path);
		if (['/llms.txt', '/sitemap.xml', '/index.md', '/llms-full.txt'].includes(path))
			for (const id of PILOT_IDS) assert.ok(text.includes(`/practices/${id}`), path);
	}
	assert.equal((await server.fetch('/practices/800004?preview=true')).status, 404);
	const xml = (await read('/sitemap.xml')).text;
	assert.ok(!/\.md|dashboard|cdn-cgi|<loc>[^<]*\?/.test(xml));
});

test('Astro and Markdown escape hostile prose/code, and published invalid bodies fail closed without caching', async () => {
	const hostile = structuredClone(pilots[2]);
	hostile.title = '</title></script><script>CANARY_XSS</script>" onload="CANARY_ATTRIBUTE';
	hostile.body.artifacts[0].code = '```\n<script>CANARY_CODE</script>';
	await storePilot(db, 800005, hostile);
	const html = await read('/practices/800005');
	const visit = (node) => {
		if (node.tagName === 'script')
			assert.ok(
				!node.childNodes.some((child) => child.value?.includes('CANARY_')) ||
					node.attrs.some((a) => a.name === 'type' && a.value === 'application/ld+json'),
			);
		assert.ok(!node.attrs?.some((a) => /^on/i.test(a.name)));
		for (const child of node.childNodes ?? []) visit(child);
	};
	visit(parse(html.text));
	assert.match(html.text, /&lt;script&gt;CANARY/);
	const schemas = [...html.text.matchAll(/<script type="application\/ld\+json">(.*?)<\/script>/gs)];
	assert.ok(schemas.length);
	for (const [, json] of schemas) JSON.parse(json);
	assert.match((await read('/practices/800005.md')).text, /````sql/);
	const rid = await storePilot(db, 800006, pilots[0], false);
	await db.prepare("UPDATE CatalogRevisions SET body_json = '{}' WHERE revision_id = ?").bind(rid).run();
	await db.batch([
		db.prepare("INSERT INTO CatalogPublications VALUES (800006, ?, '2026-10-30')").bind(rid),
		db.prepare('UPDATE CatalogEntries SET published_revision_id = ? WHERE practice_id = 800006').bind(rid),
	]);
	const broken = await read('/practices/800006');
	assert.equal(broken.response.status, 503);
	assert.equal(broken.response.headers.get('Cache-Control'), 'no-store');
	assert.match(broken.text, /temporarily unavailable/);
});
