import { readdir, readFile } from 'node:fs/promises';
import { posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from '@babel/parser';

function moduleReferences(file, source) {
	const references = [];
	const tree = parse(source, { sourceFilename: file, sourceType: 'unambiguous', plugins: ['typescript'], createImportExpressions: true });
	const add = (node) => {
		if (node?.type === 'StringLiteral') references.push(node.value);
		else if (node?.type === 'TemplateLiteral' && node.expressions.length === 0) references.push(node.quasis[0].value.cooked);
		else references.push(null);
	};
	const visit = (node) => {
		if (!node || typeof node !== 'object') return;
		if (['ImportDeclaration', 'ExportNamedDeclaration', 'ExportAllDeclaration'].includes(node.type)) {
			if (node.source) add(node.source);
		} else if (node.type === 'TSImportType') {
			add(node.argument);
		} else if (node.type === 'TSExternalModuleReference') {
			add(node.expression);
		} else if (node.type === 'ImportExpression') {
			add(node.source);
		} else if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require') {
			add(node.arguments[0]);
		}
		for (const child of Object.values(node)) {
			if (Array.isArray(child)) child.forEach(visit);
			else if (child && typeof child === 'object') visit(child);
		}
	};
	visit(tree);
	return references;
}

// Pure input/output makes the guard testable without touching application files.
export function checkBoundaries(files) {
	const errors = [];
	for (const [file, source] of Object.entries(files)) {
		const browser = file.startsWith('public/');
		const server = file.startsWith('src/');
		if (!browser && !server) continue;
		if (browser && /(?:\.(?:ts|tsx|sql|map)$|(?:^|\/)(?:wrangler\.[^/]+|\.env(?:\.[^/]+)?|\.dev\.vars(?:\.[^/]+)?))/.test(file)) {
			errors.push(`${file}: server/configuration artifact must not be published`);
		}
		const references = [];
		if (/\.[cm]?[jt]sx?$/.test(file)) references.push(...moduleReferences(file, source));
		if (server && file.endsWith('.astro')) {
			const frontmatter = /^---\r?\n([\s\S]*?)\r?\n---/.exec(source)?.[1] ?? '';
			references.push(...moduleReferences(`${file}.ts`, frontmatter));
			// Browser scripts in Astro must be external public files. No server-import backdoor in inline code.
			for (const [, attributes, body] of source.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
				const src = /\bsrc\s*=\s*['"]([^'"]+)['"]/i.exec(attributes)?.[1];
				if (src && (!src.startsWith('/') || !Object.hasOwn(files, `public${src}`))) {
					errors.push(`${file}: browser script sources must be public assets`);
				}
				if (/\btype\s*=\s*['"]application\/ld\+json['"]/.test(attributes)) continue;
				if (body.trim()) {
					for (const ref of moduleReferences(`${file}.browser.js`, body)) {
						if (ref === null || !ref.startsWith('/') || !Object.hasOwn(files, `public${ref}`))
							errors.push(`${file}: browser script imports must be public assets`);
					}
				}
			}
		}
		if (browser && file.endsWith('.html')) {
			for (const [, attributes, body] of source.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
				const src = /\bsrc\s*=\s*['"]([^'"]+)['"]/i.exec(attributes)?.[1];
				const type = /\btype\s*=\s*['"]([^'"]+)['"]/i.exec(attributes)?.[1];
				if (src) references.push(src);
				else if (!type || ['module', 'text/javascript', 'application/javascript'].includes(type.toLowerCase())) {
					references.push(...moduleReferences(`${file}.js`, body));
				}
			}
		}
		for (const specifier of references) {
			if (specifier === null) {
				errors.push(`${file}: computed module imports cannot be checked`);
				continue;
			}
			const local = specifier.startsWith('.') || specifier.startsWith('/');
			if (!local) {
				if (browser) errors.push(`${file}: browser imports must be local public assets (${specifier})`);
				continue;
			}
			const path = specifier.split(/[?#]/)[0];
			const target = posix.normalize(browser && path.startsWith('/') ? `public${path}` : posix.join(posix.dirname(file), path));
			const boundary = browser ? 'public/' : 'src/';
			if (!target.startsWith(boundary)) {
				errors.push(`${file}: import crosses the ${boundary} boundary (${specifier})`);
				continue;
			}
			const candidates = browser ? [target] : [target, `${target}.ts`, `${target}/index.ts`, target.replace(/\.js$/, '.ts')];
			if (!candidates.some((candidate) => Object.hasOwn(files, candidate))) errors.push(`${file}: unresolved local import (${specifier})`);
		}
	}
	return errors;
}

async function readSources(directory, prefix) {
	const files = {};
	for (const entry of await readdir(directory, { withFileTypes: true })) {
		const path = `${directory}/${entry.name}`;
		const key = `${prefix}/${entry.name}`;
		if (entry.isSymbolicLink()) throw new Error(`${key}: symlinks are not allowed in application source/assets`);
		if (entry.isDirectory()) Object.assign(files, await readSources(path, key));
		else files[key] = /\.(?:[cm]?[jt]sx?|html|astro)$/.test(key) ? await readFile(path, 'utf8') : '';
	}
	return files;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
	const root = fileURLToPath(new URL('../', import.meta.url));
	const files = Object.assign({}, ...(await Promise.all(['src', 'public'].map((name) => readSources(`${root}${name}`, name)))));
	const errors = checkBoundaries(files);
	if (errors.length) {
		console.error(errors.join('\n'));
		process.exitCode = 1;
	} else console.log('Server/browser import boundaries and public artifacts verified.');
}
