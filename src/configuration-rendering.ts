import type { Practice } from './practice-data';
import { escapeHtml } from './html-escaping';

// Only the explicit expression field is presented as a paste-ready expression.
type ConfigurationSection = { heading: string; kind: 'expression' | 'configuration'; text: string };

export function configurationSections(p: Practice): ConfigurationSection[] {
	const sections: ConfigurationSection[] = [];
	if (p.expression?.trim()) sections.push({ heading: 'Example expression', kind: 'expression', text: p.expression });
	if (p.expressions_configuration_details?.trim() && p.expressions_configuration_details !== p.expression) {
		sections.push({ heading: 'Configuration guidance', kind: 'configuration', text: p.expressions_configuration_details });
	}
	return sections;
}

export function configurationHtml(p: Practice): string {
	return configurationSections(p)
		.map(
			({ heading, kind, text }) =>
				`<section><h2>${heading}</h2><div class="code-block is-wrapped" data-copy-kind="${kind}"><pre tabindex="0" aria-label="${heading}"><code>${escapeHtml(text)}</code></pre></div></section>`,
		)
		.join('');
}

export function configurationMarkdown(p: Practice): string {
	return configurationSections(p)
		.map(({ heading, text }) => {
			// Stored backticks must not close the Markdown fence early.
			const fence = '`'.repeat(Math.max(3, ...Array.from(text.matchAll(/`+/g), (m) => m[0].length + 1)));
			return `\n## ${heading}\n\n${fence}text\n${text}\n${fence}\n`;
		})
		.join('');
}
