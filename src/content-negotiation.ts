// Only explicitly requested Markdown opts in. Wildcards retain the browser's HTML default.
// Honor specificity (text/markdown;q=0 overrides text/*) and quality preferences.
export function prefersMarkdown(accept: string | null): boolean {
	if (!accept) return false;
	const ranges = accept
		.toLowerCase()
		.split(',')
		.map((entry) => {
			const [type, ...parameters] = entry.trim().split(';');
			const quality = parameters.find((p) => p.trim().startsWith('q='));
			const raw = quality ? quality.trim().slice(2) : '1';
			const q = /^(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$/.test(raw) ? Number(raw) : 0;
			return { type: type.trim(), q };
		});
	const markdown = ranges.find((range) => range.type === 'text/markdown');
	if (!markdown || markdown.q === 0) return false;
	const html =
		ranges.find((range) => range.type === 'text/html') ??
		ranges.find((range) => range.type === 'text/*') ??
		ranges.find((range) => range.type === '*/*');
	return markdown.q >= (html?.q ?? 0);
}
