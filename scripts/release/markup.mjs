import { parse } from 'parse5';

export function elements(html) {
	const nodes = [];
	function visit(node) {
		if (node.tagName) nodes.push(node);
		for (const child of node.childNodes ?? []) visit(child);
	}
	visit(typeof html === 'string' ? parse(html) : html);
	return nodes;
}
export const attr = (node, name) => node.attrs?.find((a) => a.name === name)?.value;
export const text = (node) => (node.nodeName === '#text' ? node.value : (node.childNodes ?? []).map(text).join(''));
