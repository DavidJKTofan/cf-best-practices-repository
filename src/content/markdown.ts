import { DISCLAIMER, SITE_URL, practiceMarkdown } from '../content-rendering';
import type { CatalogDetail } from '../modules/catalog/v2-projection';
import { readingSections } from './presentation';

export function markdownText(value: string): string {
	return value.replace(/([\\`*_{}\[\]<>()#+.!|~-])/g, '\\$1');
}
export function fencedCode(value: string, language = 'text'): string {
	const longest = Math.max(2, ...[...value.matchAll(/`+/g)].map(([run]) => run.length));
	const fence = '`'.repeat(longest + 1);
	return `${fence}${/^[a-z0-9+-]+$/i.test(language) ? language : 'text'}\n${value}\n${fence}\n`;
}
export function entryMarkdown(entry: CatalogDetail): string {
	if (entry.schemaVersion === 0) return `${practiceMarkdown(entry.body)}\n---\n\n${DISCLAIMER}\n`;
	const sections = readingSections(entry).map((section) => {
		const items = section.items?.map((text, index) => `${section.ordered ? `${index + 1}.` : '-'} ${markdownText(text)}`).join('\n') ?? '';
		const blocks =
			section.blocks
				?.map((block) =>
					block.kind === 'code'
						? `### ${markdownText(block.filename)}\n\n${markdownText(block.purpose)}\n\n${fencedCode(block.code, block.language)}`
						: `${block.kind === 'warning' ? '> ' : ''}${markdownText(block.text)}`,
				)
				.join('\n\n') ?? '';
		return `## ${section.title}\n\n${section.paragraphs?.map(markdownText).join('\n\n') ?? ''}${items}${section.diagram ? markdownText(section.diagram) : ''}${blocks}`;
	});
	sections.unshift(
		`## Publication status\n\n${entry.lifecycle.state}${entry.lifecycle.reason ? ` — ${markdownText(entry.lifecycle.reason)}` : ''}${entry.lifecycle.supersededBy ? `\n\nReplacement: ${SITE_URL}/practices/${entry.lifecycle.supersededBy}` : ''}`,
	);
	return `# ${markdownText(entry.title)}\n\nCanonical URL: ${SITE_URL}${entry.canonicalPath}\nPractice ID: ${entry.practiceId}\nRevision: ${entry.revisionId}\n\n${markdownText(entry.summary)}\n\n- Type: ${entry.type}\n- Products: ${entry.products.join(', ')}\n- Evidence: ${entry.evidence}\n- Maturity: ${entry.maturity}\n- Editorial update: ${entry.modifiedAt ?? 'Not recorded'}\n- Fact verified: ${entry.factVerifiedAt ?? 'Not recorded'}\n- Review due: ${entry.reviewDueAt ?? 'Not recorded'}\n\n${sections.join('\n\n')}\n\n## Sources\n\n${entry.sources.map((s) => `- [${markdownText(s.title)}](<${s.url.replace(/[<>\r\n]/g, (c) => encodeURIComponent(c))}>)`).join('\n')}\n\n## Related guidance\n\n[More in this family](${SITE_URL}/families/${entry.primaryFamily})\n\n---\n\n${DISCLAIMER}\n`;
}
