import { escapeHtml } from '../../content-rendering';
import { readingSections } from '../../content/presentation';
import { entryMarkdown } from '../../content/markdown';
import type { getDraft } from './queries';

export function draftDetail(draft: Awaited<ReturnType<typeof getDraft>>) {
	return {
		...draft.content,
		lifecycle: draft.lifecycle,
		legacyClassification: null,
		practiceId: draft.practiceId,
		revisionId: null,
		v1Eligible: false,
		canonicalPath: `/practices/${draft.practiceId}`,
		detailPath: `/api/v2/entries/${draft.practiceId}`,
	};
}
export function previewDraft(draft: Awaited<ReturnType<typeof getDraft>>, markdown: boolean): Response {
	const entry = draftDetail(draft);
	const banner = `PRIVATE PREVIEW — draft version ${draft.version}; not published`;
	const body = markdown
		? `${banner}\n\n${entryMarkdown(entry)}`
		: `<!doctype html><html lang="en"><head><meta charset="utf-8">
		<meta name="viewport" content="width=device-width"><meta name="robots" content="noindex,nofollow"><title>Private draft preview</title>
		<link rel="stylesheet" href="/editorial.css"></head><body><main class="preview"><p class="eyebrow">${banner}</p>
		<h1>${escapeHtml(entry.title)}</h1><p>${escapeHtml(entry.summary)}</p>
		<p>Lifecycle: ${escapeHtml(entry.lifecycle.state)}. ${escapeHtml(entry.lifecycle.reason ?? '')}</p>
		${readingSections(entry)
			.map(
				(s) => `<section><h2>${escapeHtml(s.title)}</h2>
			${s.paragraphs?.map((p) => `<p>${escapeHtml(p)}</p>`).join('') ?? ''}
			${s.items ? `<${s.ordered ? 'ol' : 'ul'}>${s.items.map((p) => `<li>${escapeHtml(p)}</li>`).join('')}</${s.ordered ? 'ol' : 'ul'}>` : ''}
			${s.diagram ? `<pre>${escapeHtml(s.diagram)}</pre>` : ''}
			${s.blocks?.map((b) => (b.kind === 'code' ? `<h3>${escapeHtml(b.filename)}</h3><p>${escapeHtml(b.purpose)}</p><pre><code>${escapeHtml(b.code)}</code></pre>` : `<p>${escapeHtml(b.text)}</p>`)).join('') ?? ''}</section>`,
			)
			.join('')}
		<h2>Sources & freshness</h2><p>Evidence: ${escapeHtml(entry.evidence)}; maturity: ${escapeHtml(entry.maturity)};
		fact verified: ${escapeHtml(entry.factVerifiedAt ?? 'Not recorded')}; review due: ${escapeHtml(entry.reviewDueAt ?? 'Not recorded')}</p>
		<ul>${entry.sources.map((s) => `<li><a href="${escapeHtml(s.url)}" rel="noreferrer">${escapeHtml(s.title)}</a></li>`).join('')}</ul></main></body></html>`;
	return new Response(body, {
		headers: {
			'Content-Type': markdown ? 'text/markdown; charset=utf-8' : 'text/html; charset=utf-8',
			'Cache-Control': 'private, no-store',
			'X-Robots-Tag': 'noindex, nofollow',
			'Content-Signal': 'search=no, ai-input=no, ai-train=no',
			'X-Content-Type-Options': 'nosniff',
			'Referrer-Policy': 'no-referrer',
			'Content-Security-Policy': "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
		},
	});
}
