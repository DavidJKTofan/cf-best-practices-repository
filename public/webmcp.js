// Progressive enhancement for supporting browsers: public read tools only.
const context = document.modelContext ?? navigator.modelContext;
if (context?.registerTool) {
	const controller = new AbortController();
	addEventListener('pagehide', (event) => {
		if (!event.persisted) controller.abort();
	});
	try {
		await context.registerTool(
			{
				name: 'search_cloudflare_practices',
				description:
					'Search sourced Cloudflare L7 best practices, including prerequisites, configuration, and official references. Public read-only access.',
				inputSchema: {
					type: 'object',
					properties: { search: { type: 'string', maxLength: 200, description: 'Literal substring to find in practice content.' } },
					additionalProperties: false,
				},
				async execute(input) {
					if (!input || typeof input !== 'object' || (input.search !== undefined && typeof input.search !== 'string'))
						throw new Error('search must be a string');
					const url = new URL('/api/practices', location.origin);
					if (input.search) url.searchParams.set('search', input.search.slice(0, 200));
					const response = await fetch(url, { signal: controller.signal });
					if (!response.ok) throw new Error(`Practice search failed (HTTP ${response.status})`);
					const body = await response.json();
					return { content: [{ type: 'text', text: JSON.stringify(body) }] };
				},
			},
			{ signal: controller.signal },
		);
		await context.registerTool(
			{
				name: 'search_cloudflare_catalog',
				description:
					'Retrieve a bounded page of published catalog summaries. Search title/summary only; fetch detailPath for complete JSON. Read-only.',
				inputSchema: {
					type: 'object',
					properties: {
						q: { type: 'string', maxLength: 200 },
						family: { type: 'string', maxLength: 80 },
						product: { type: 'string', maxLength: 80 },
						outcome: { type: 'string', maxLength: 80 },
						type: {
							type: 'string',
							enum: ['legacy-practice', 'recommendation', 'rule-policy', 'reference-architecture', 'implementation-guide'],
						},
						page: { type: 'integer', minimum: 1, maximum: 10000 },
						pageSize: { type: 'integer', minimum: 1, maximum: 50 },
					},
					additionalProperties: false,
				},
				async execute(input) {
					if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Expected catalog filters');
					const url = new URL('/api/v2/entries', location.origin);
					for (const key of ['q', 'family', 'product', 'outcome', 'type']) {
						if (input[key] !== undefined && typeof input[key] !== 'string') throw new Error(`${key} must be a string`);
						if (input[key]) url.searchParams.set(key, [...input[key]].slice(0, key === 'q' ? 200 : 80).join(''));
					}
					for (const [key, max] of [
						['page', 10000],
						['pageSize', 50],
					]) {
						if (input[key] !== undefined) {
							if (!Number.isInteger(input[key]) || input[key] < 1 || input[key] > max) throw new Error(`Invalid ${key}`);
							url.searchParams.set(key, String(input[key]));
						}
					}
					const response = await fetch(url, { signal: controller.signal });
					if (!response.ok) throw new Error(`Catalog search failed (HTTP ${response.status})`);
					return { content: [{ type: 'text', text: JSON.stringify(await response.json()) }] };
				},
			},
			{ signal: controller.signal },
		);
	} catch (err) {
		console.error(err);
	}
}
