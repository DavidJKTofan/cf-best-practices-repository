import type { Practice } from './practice-data';
import { escapeHtml } from './html-escaping';
import { configurationHtml, configurationMarkdown } from './configuration-rendering';
export { escapeHtml } from './html-escaping';

export const SITE_URL = 'https://db.automatic-demo.com';
export const SITE_NAME = 'Cloudflare Field Guide';
export const SITE_DESCRIPTION =
	'Unofficial, sourced recommendations and implementation patterns for the Cloudflare platform. Understand the prerequisites, failure modes, and trade-offs before deploying.';
export const CONTENT_SIGNAL = 'search=yes, ai-input=yes, ai-train=no';
export const DISCLAIMER =
	'A personal educational project, not official Cloudflare guidance. Validate recommendations against the linked documentation and your plan entitlements. Examples and thresholds must be adapted and observed before enforcement. Content is provided as is, without warranty.';

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
	const sources = [safeUrl(p.source_reference), safeUrl(p.feature_url)].filter((url): url is string => !!url);
	return `# ${markdownText(p.title)}\n\nCanonical URL: ${url}\nPractice ID: ${p.practice_id}\n\n${markdownText(p.description)}\n\n${fields.map(([key, value]) => `- **${key}:** ${markdownText(value)}`).join('\n')}\n${section('Prerequisites', p.prerequisites)}${configurationMarkdown(p)}${section('Notes', p.notes)}\n## Sources\n\n${sources.length ? [...new Set(sources)].map((url) => `- <${url.replace(/>/g, '%3E')}>`).join('\n') : 'No source URL recorded.'}\n`;
}

export function collectionMarkdown(practices: Practice[]): string {
	return `# ${SITE_NAME}\n\n${SITE_DESCRIPTION}\n\n${DISCLAIMER}\n\n${practices.length} practices. Cite the canonical practice URLs and verify the official sources before applying advice.\n\n## Machine-readable access\n\n- [Agent index](${SITE_URL}/llms.txt)\n- [JSON API](${SITE_URL}/api/practices)\n- [Paginated published summaries](${SITE_URL}/api/v2/entries): title/summary search and selective JSON detail retrieval; this Markdown export remains the legacy catalog\n- [API documentation](${SITE_URL}/api-docs)\n- [OpenAPI](${SITE_URL}/openapi.json)\n\n---\n\n${practices.map(practiceMarkdown).join('\n---\n\n')}`;
}

export function homeRows(practices: Practice[]): string {
	const slug = (value: string | null) => (value ?? 'none').toLowerCase().replace(/[^a-z0-9]+/g, '-');
	return practices
		.map(
			(p) =>
				`<tr class="row" id="practice-${p.practice_id}"><td class="col-title"><a class="practice-title" href="/practices/${p.practice_id}">${escapeHtml(p.title)}</a><p class="desc">${escapeHtml(p.description)}</p></td>${[
					['category', p.category_name],
					['domain', p.domain],
					['level', p.recommendation_level],
					['impact', p.impact_level],
					['difficulty', p.difficulty_level],
					['feature', p.feature_name],
				]
					.map(([field, value]) => {
						const rating = field === 'impact' || field === 'difficulty';
						const classes = `col-${field}${rating ? ` meter ${field}-${slug(value)}` : field === 'level' ? ` level-${slug(value)}` : ''}`;
						const text = escapeHtml(value ?? 'Not rated');
						const content = field === 'domain' ? `<span class="badge domain-${slug(value)}">${text}</span>` : text;
						return `<td class="${classes}" data-label="${field === 'impact' ? 'Impact' : field === 'difficulty' ? 'Difficulty' : field}">${content}</td>`;
					})
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
	const section = (heading: string, text: string | null) =>
		text ? `<section><h2>${heading}</h2><p class="prose-text">${escapeHtml(text)}</p></section>` : '';
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
	<title>${escapeHtml(p.title)} | ${SITE_NAME}</title><meta name="description" content="${escapeHtml(p.description.slice(0, 180))}">
	<link rel="canonical" href="${url}"><link rel="alternate" type="text/markdown" href="${path}.md">
	<meta name="color-scheme" content="light dark"><script src="/theme-init.js"></script><link rel="stylesheet" href="/style.css"><link rel="icon" href="/favicon.png">
	<meta property="og:type" content="article"><meta property="og:title" content="${escapeHtml(p.title)}"><meta property="og:description" content="${escapeHtml(p.description.slice(0, 180))}"><meta property="og:url" content="${url}"><meta property="og:site_name" content="${SITE_NAME}">
	<meta name="twitter:card" content="summary"><script type="module" src="/theme.js"></script><script type="module" src="/code-blocks.js"></script>
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
	<header class="site-header"><div class="container header-inner"><a class="brand" href="/"><img src="/favicon.png" width="28" height="28" alt=""><span class="brand-name">${SITE_NAME}</span></a><div class="header-actions"><a class="btn btn-link format-link" href="${path}.md">Markdown</a><button class="icon-btn theme-switch" type="button" aria-label="Toggle color theme" title="Toggle color theme"><span class="icon-moon" aria-hidden="true">☾</span><span class="icon-sun" aria-hidden="true">☀</span></button></div></div></header>
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
	${section('Prerequisites', p.prerequisites)}${configurationHtml(p)}${section('Notes', p.notes)}
	<section><h2>Sources and freshness</h2><ul>${source ? `<li><a href="${escapeHtml(source)}">Source documentation</a></li>` : '<li>No source URL recorded.</li>'}${feature ? `<li><a href="${escapeHtml(feature)}">${escapeHtml(p.feature_name)} documentation</a></li>` : ''}</ul><p>${updated ? `Updated <time datetime="${updated}">${updated.slice(0, 10)}</time>` : 'Update date not recorded.'}</p></section>
	</article></main><footer class="site-footer"><div class="container"><p>${DISCLAIMER}</p><p><a href="/api-docs">API documentation</a> · <a href="/llms.txt">Agent index</a> · <a href="/#practice-${p.practice_id}">Open in interactive table</a></p></div></footer></body></html>`;
}
