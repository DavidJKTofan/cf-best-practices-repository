import type { Practice } from './practice-data';

export const SITE_URL = 'https://db.automatic-demo.com';
export const SITE_NAME = 'Cloudflare L7 Best Practices';
export const SITE_DESCRIPTION =
	'Sourced security, performance, and reliability best practices for Cloudflare application (Layer 7) services, with prerequisites and configuration examples.';
export const CONTENT_SIGNAL = 'search=yes, ai-input=yes, ai-train=no';
export const DISCLAIMER =
	'A personal educational project, not official Cloudflare guidance. Validate recommendations against the linked documentation and your plan entitlements. Examples and thresholds must be adapted and observed before enforcement. Content is provided as is, without warranty.';

export function escapeHtml(value: unknown): string {
	return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

function markdownText(value: string | null): string {
	return (value ?? '').replace(/([\\`*_{}\[\]<>()#+.!|~-])/g, '\\$1');
}

export function safeUrl(value: string | null): string | null {
	try {
		const url = new URL(value ?? '');
		return ['https:', 'http:'].includes(url.protocol) ? url.href : null;
	} catch {
		return null;
	}
}

export function modifiedDate(value: string | null): string | undefined {
	if (!value) return undefined;
	const iso = value.includes('T') ? value : `${value.replace(' ', 'T')}Z`;
	const date = new Date(iso);
	return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

export function jsonLd(data: unknown): string {
	// JSON inside a script is raw text: prevent stored content from closing the element.
	return `<script type="application/ld+json">${JSON.stringify(data).replace(/</g, '\\u003c')}</script>`;
}

export function discoveryLinks(canonical: string, markdown: string): string {
	return `<${SITE_URL}${canonical}>; rel="canonical", <${SITE_URL}${markdown}>; rel="alternate"; type="text/markdown", </.well-known/api-catalog>; rel="api-catalog", </openapi.json>; rel="service-desc"; type="application/vnd.oai.openapi+json", </api-docs>; rel="service-doc"; type="text/html", </llms.txt>; rel="describedby"; type="text/plain", </sitemap.xml>; rel="sitemap"; type="application/xml"`;
}

export function practiceMarkdown(p: Practice): string {
	const url = `${SITE_URL}/practices/${p.practice_id}`;
	const fields = [
		['Domain', p.domain],
		['Category', p.category_name],
		['Feature', p.feature_name],
		['Recommendation level', p.recommendation_level],
		['Impact', p.impact_level ?? 'Not rated'],
		['Difficulty', p.difficulty_level ?? 'Not rated'],
		['Updated', modifiedDate(p.updated_at) ?? 'Not recorded'],
	];
	const section = (heading: string, text: string | null) => (text ? `\n## ${heading}\n\n${markdownText(text)}\n` : '');
	const config = p.expressions_configuration_details;
	// A longer fence prevents configuration text containing backticks from breaking out of its code block.
	const fence = '`'.repeat(Math.max(3, ...Array.from(config?.matchAll(/`+/g) ?? [], (m) => m[0].length + 1)));
	const sources = [safeUrl(p.source_reference), safeUrl(p.feature_url)].filter((url): url is string => !!url);
	return `# ${markdownText(p.title)}\n\nCanonical URL: ${url}\nPractice ID: ${p.practice_id}\n\n${markdownText(p.description)}\n\n${fields.map(([key, value]) => `- **${key}:** ${markdownText(value)}`).join('\n')}\n${section('Prerequisites', p.prerequisites)}${config ? `\n## Configuration / expression\n\n${fence}text\n${config}\n${fence}\n` : ''}${section('Notes', p.notes)}\n## Sources\n\n${sources.length ? [...new Set(sources)].map((url) => `- <${url.replace(/>/g, '%3E')}>`).join('\n') : 'No source URL recorded.'}\n`;
}

export function collectionMarkdown(practices: Practice[]): string {
	return `# ${SITE_NAME}\n\n${SITE_DESCRIPTION}\n\n${DISCLAIMER}\n\n${practices.length} practices. Cite the canonical practice URLs and verify the official sources before applying advice.\n\n## Machine-readable access\n\n- [Agent index](${SITE_URL}/llms.txt)\n- [JSON API](${SITE_URL}/api/practices)\n- [API documentation](${SITE_URL}/api-docs)\n- [OpenAPI](${SITE_URL}/openapi.json)\n\n---\n\n${practices.map(practiceMarkdown).join('\n---\n\n')}`;
}

export function homeRows(practices: Practice[]): string {
	return practices
		.map(
			(p) =>
				`<tr class="row" id="practice-${p.practice_id}"><td class="col-title"><a href="/practices/${p.practice_id}">${escapeHtml(p.title)}</a><p class="desc">${escapeHtml(p.description)}</p></td>${[
					['category', p.category_name],
					['domain', p.domain],
					['level', p.recommendation_level],
					['impact', p.impact_level],
					['difficulty', p.difficulty_level],
					['feature', p.feature_name],
				]
					.map(([field, value]) => `<td class="col-${field}" data-label="${field}">${escapeHtml(value ?? 'Not rated')}</td>`)
					.join('')}</tr>`,
		)
		.join('');
}

export function collectionSchema(practices: Practice[]): unknown {
	return {
		'@context': 'https://schema.org',
		'@type': 'CollectionPage',
		'@id': `${SITE_URL}/#collection`,
		url: `${SITE_URL}/`,
		name: SITE_NAME,
		description: SITE_DESCRIPTION,
		inLanguage: 'en',
		mainEntity: {
			'@type': 'ItemList',
			numberOfItems: practices.length,
			itemListElement: practices.map((p, i) => ({
				'@type': 'ListItem',
				position: i + 1,
				url: `${SITE_URL}/practices/${p.practice_id}`,
				name: p.title,
			})),
		},
	};
}

export function practiceHtml(p: Practice): string {
	const path = `/practices/${p.practice_id}`;
	const url = `${SITE_URL}${path}`;
	const source = safeUrl(p.source_reference);
	const feature = safeUrl(p.feature_url);
	const updated = modifiedDate(p.updated_at);
	const section = (heading: string, text: string | null, code = false) =>
		text
			? `<section><h2>${heading}</h2>${code ? `<pre tabindex="0"><code>${escapeHtml(text)}</code></pre>` : `<p class="prose-text">${escapeHtml(text)}</p>`}</section>`
			: '';
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
	<title>${escapeHtml(p.title)} | ${SITE_NAME}</title><meta name="description" content="${escapeHtml(p.description.slice(0, 180))}">
	<link rel="canonical" href="${url}"><link rel="alternate" type="text/markdown" href="${path}.md">
	<link rel="stylesheet" href="/style.css"><link rel="icon" href="/favicon.png"><meta name="color-scheme" content="light dark">
	<meta property="og:type" content="article"><meta property="og:title" content="${escapeHtml(p.title)}"><meta property="og:description" content="${escapeHtml(p.description.slice(0, 180))}"><meta property="og:url" content="${url}"><meta property="og:site_name" content="${SITE_NAME}">
	<meta name="twitter:card" content="summary"><script type="module" src="/theme.js"></script>
	${jsonLd({ '@context': 'https://schema.org', '@type': 'TechArticle', '@id': url, url, headline: p.title, description: p.description, inLanguage: 'en', dateModified: updated, citation: source ?? undefined, about: p.feature_name ?? p.domain, isPartOf: { '@type': 'WebSite', name: SITE_NAME, url: `${SITE_URL}/` } })}
	${jsonLd({
		'@context': 'https://schema.org',
		'@type': 'BreadcrumbList',
		itemListElement: [
			{ '@type': 'ListItem', position: 1, name: SITE_NAME, item: `${SITE_URL}/` },
			{ '@type': 'ListItem', position: 2, name: p.title, item: url },
		],
	})}
	</head><body><a class="skip-link" href="#practice">Skip to practice</a>
	<header class="site-header"><div class="container header-inner"><a class="brand" href="/">${SITE_NAME}</a><a href="${path}.md">Markdown</a></div></header>
	<main id="practice" class="container practice-page"><nav aria-label="Breadcrumb"><a href="/">All practices</a> / Practice ${p.practice_id}</nav>
	<article><header><p class="eyebrow">${escapeHtml(p.domain)} / ${escapeHtml(p.category_name)}</p><h1>${escapeHtml(p.title)}</h1><p class="practice-lede">${escapeHtml(p.description)}</p></header>
	<dl class="practice-facts">${[
		['Feature', p.feature_name],
		['Level', p.recommendation_level],
		['Impact', p.impact_level],
		['Difficulty', p.difficulty_level],
	]
		.map(([key, value]) => `<div><dt>${key}</dt><dd>${escapeHtml(value ?? 'Not rated')}</dd></div>`)
		.join('')}</dl>
	${section('Prerequisites', p.prerequisites)}${section('Configuration / expression', p.expressions_configuration_details, true)}${section('Notes', p.notes)}
	<section><h2>Sources and freshness</h2><ul>${source ? `<li><a href="${escapeHtml(source)}">Source documentation</a></li>` : '<li>No source URL recorded.</li>'}${feature ? `<li><a href="${escapeHtml(feature)}">${escapeHtml(p.feature_name)} documentation</a></li>` : ''}</ul><p>${updated ? `Updated <time datetime="${updated}">${updated.slice(0, 10)}</time>` : 'Update date not recorded.'}</p></section>
	</article></main><footer class="site-footer"><div class="container"><p>${DISCLAIMER}</p><p><a href="/api-docs">API documentation</a> · <a href="/llms.txt">Agent index</a> · <a href="/#practice-${p.practice_id}">Open in interactive table</a></p></div></footer></body></html>`;
}
