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
	} catch (err) {
		console.error(err);
	}
}
