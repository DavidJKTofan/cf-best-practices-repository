import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const source = await readFile('public/catalog-search.js', 'utf8');

function harness() {
	const events = new Map(),
		timers = new Map(),
		requests = [];
	let serial = 0;
	const form = {
		action: 'https://catalog.example.com/catalog',
		values: [
			['q', 'D1'],
			['page', '9'],
		],
	};
	const attributes = new Map();
	let currentView;
	const view = {
		querySelector: (selector) => (selector === 'form' ? form : null),
		setAttribute: (key, value) => attributes.set(key, value),
		removeAttribute: (key) => attributes.delete(key),
	};
	currentView = view;
	const status = { textContent: '' };
	const document = {
		querySelector: (selector) =>
			selector === '[data-catalog-view]' ? currentView : selector === '[data-catalog-status]' ? status : metadata.get(selector),
		addEventListener: (type, callback) => events.set(type, callback),
		importNode: (node) => node,
	};
	const metadata = new Map();
	const history = [];
	const browser = {
		location: new URL(form.action),
		history: Object.fromEntries(
			['pushState', 'replaceState'].map((method) => [
				method,
				(_state, _title, path) => {
					history.push({ method, path });
					browser.location = new URL(path, browser.location);
				},
			]),
		),
		addEventListener: (type, callback) => events.set(type, callback),
		setTimeout: (callback, delay) => {
			timers.set(++serial, { callback, delay });
			return serial;
		},
		clearTimeout: (id) => timers.delete(id),
		fetch: (url, options) => new Promise((resolve) => requests.push({ url, options, resolve })),
	};
	let parsed;
	const functions = vm.runInNewContext(`${source.replace(/^export /gm, '')}; ({searchUrl, enhanceCatalog})`, {
		URL,
		URLSearchParams,
		AbortController,
		DOMParser: class {
			parseFromString() {
				return parsed;
			}
		},
		FormData: class {
			constructor(target) {
				return new URLSearchParams(target.values);
			}
		},
	});
	functions.enhanceCatalog(document, browser);
	return {
		...functions,
		form,
		status,
		requests,
		events,
		attributes,
		history,
		browser,
		document,
		input: { form, name: 'q', tagName: 'INPUT' },
		success(query = 'D1') {
			const nextInput = {
				name: 'q',
				tagName: 'INPUT',
				value: query,
				focus() {
					document.activeElement = this;
				},
				setSelectionRange(start, end) {
					this.selectionStart = start;
					this.selectionEnd = end;
				},
			};
			const nextForm = { ...form, elements: { namedItem: (name) => (name === 'q' ? nextInput : null) } };
			nextInput.form = nextForm;
			const disclosure = { open: false };
			const count = { textContent: '1 result' };
			const replacement = {
				...view,
				contains: (node) => node === nextInput,
				querySelector: (selector) =>
					({ form: nextForm, details: disclosure, '.results-count': count, '[data-catalog-results]': count })[selector],
			};
			currentView.contains = (node) => node === document.activeElement;
			const priorQuery = currentView.querySelector;
			currentView.querySelector = (selector) => (selector === 'details' ? { open: true } : priorQuery(selector));
			currentView.replaceWith = (node) => {
				currentView = node;
			};
			const canonical = { href: `https://public-canonical.example.com/catalog?q=${query}` };
			const markdown = { getAttribute: () => `/catalog.md?q=${query}` };
			metadata.set('[data-markdown-link]', {
				setAttribute: (_name, value) => {
					markdown.updated = value;
				},
			});
			for (const selector of [
				'link[rel="canonical"]',
				'link[rel="alternate"][type="text/markdown"]',
				'meta[property="og:url"]',
				'script[type="application/ld+json"]',
			]) {
				metadata.set(selector, { replaceWith: (node) => metadata.set(selector, node) });
			}
			parsed = {
				title: 'Filtered catalog',
				querySelector: (selector) =>
					({ '[data-catalog-view]': replacement, 'link[rel="canonical"]': canonical, '[data-markdown-link]': markdown })[selector],
			};
			return { nextInput, disclosure, canonical, markdown, metadata };
		},
		run(delay) {
			for (const [id, timer] of [...timers])
				if (timer.delay === delay) {
					timers.delete(id);
					timer.callback();
				}
		},
		runOne(delay) {
			for (const [id, timer] of timers)
				if (timer.delay === delay) {
					timers.delete(id);
					timer.callback();
					break;
				}
		},
	};
}
const settle = () => new Promise(setImmediate);

test('live search keeps bounded server-side GET filtering and resets page on catalog and family forms', () => {
	const h = harness();
	const url = h.searchUrl(h.form, 'https://catalog.example.com');
	assert.equal(url.pathname, '/catalog');
	assert.equal(url.searchParams.get('q'), 'D1');
	assert.equal(url.searchParams.has('page'), false);
	h.form.action = 'https://catalog.example.com/families/cloudflare-one';
	h.form.values.push(['product', 'access']);
	assert.equal(h.searchUrl(h.form).pathname, '/families/cloudflare-one');
	assert.equal(h.searchUrl(h.form).searchParams.get('product'), 'access');
});

test('text input debounces; changing a dropdown requests updated SSR results immediately', () => {
	const h = harness();
	h.events.get('input')({ target: h.input, isComposing: false });
	assert.equal(h.requests.length, 0);
	h.run(350);
	assert.equal(h.requests.length, 1);
	assert.equal(h.requests[0].options.headers.Accept, 'text/html');
	assert.equal(h.requests[0].options.credentials, 'omit');
	assert.equal(h.requests[0].options.redirect, 'error');
	h.events.get('change')({ target: { form: h.form, tagName: 'SELECT' } });
	assert.equal(h.requests.length, 2);
	assert.equal(h.requests[0].options.signal.aborted, true);
	assert.equal(h.attributes.get('aria-busy'), 'true');
	h.events.get('pagehide')();
	assert.equal(h.requests[1].options.signal.aborted, true);
});

test('IME composition does not query until composition finishes', () => {
	const h = harness();
	h.events.get('compositionstart')({ target: h.input });
	h.events.get('input')({ target: h.input, isComposing: true });
	h.run(350);
	assert.equal(h.requests.length, 0);
	h.events.get('compositionend')({ target: h.input });
	h.run(350);
	assert.equal(h.requests.length, 1);
});

test('stale failures cannot disable newer searches; current failure preserves native form fallback', async () => {
	const h = harness();
	h.events.get('change')({ target: { form: h.form, tagName: 'SELECT' } });
	h.events.get('input')({ target: h.input, isComposing: false });
	h.run(350);
	h.requests[0].resolve(new Response('', { status: 503 }));
	await settle();
	let prevented = false;
	h.events.get('submit')({
		target: h.form,
		preventDefault: () => {
			prevented = true;
		},
	});
	assert.equal(prevented, true);
	assert.equal(h.requests.length, 3);
	h.requests[2].resolve(new Response('', { status: 503 }));
	await settle();
	assert.match(h.status.textContent, /Press Search/);
	assert.equal(h.attributes.has('aria-busy'), false);
	prevented = false;
	h.events.get('submit')({
		target: h.form,
		preventDefault: () => {
			prevented = true;
		},
	});
	assert.equal(prevented, false);
	h.events.get('pagehide')();
});

test('each request timeout belongs only to that request, not a newer request', () => {
	const h = harness();
	h.events.get('change')({ target: { form: h.form, tagName: 'SELECT' } });
	h.events.get('change')({ target: { form: h.form, tagName: 'SELECT' } });
	// A superseded request may still have its timeout queued until finally runs.
	h.runOne(10_000);
	assert.equal(h.requests[0].options.signal.aborted, true);
	assert.equal(h.requests[1].options.signal.aborted, false);
	h.runOne(10_000);
	assert.equal(h.requests[1].options.signal.aborted, true);
});

test('successful SSR replacement preserves caret/disclosure and updates canonical, Markdown, count and URL history', async () => {
	const h = harness();
	h.document.activeElement = { name: 'q', tagName: 'INPUT', value: 'D1', selectionStart: 1, selectionEnd: 2 };
	const next = h.success();
	h.events.get('input')({ target: h.input, isComposing: false });
	h.run(350);
	h.requests[0].resolve(new Response('<html></html>', { headers: { 'Content-Type': 'text/html' } }));
	await settle();
	assert.equal(h.document.activeElement, next.nextInput);
	assert.equal(next.nextInput.value, 'D1');
	assert.equal(next.nextInput.selectionStart, 1);
	assert.equal(next.nextInput.selectionEnd, 2);
	assert.equal(next.disclosure.open, true);
	assert.equal(h.document.title, 'Filtered catalog');
	assert.equal(h.status.textContent, '1 result');
	assert.equal(h.browser.location.href, 'https://catalog.example.com/catalog?q=D1');
	assert.equal(h.history[0].method, 'pushState');
	assert.equal(next.metadata.get('link[rel="canonical"]'), next.canonical);
	assert.equal(next.markdown.updated, '/catalog.md?q=D1');
	assert.equal(h.attributes.has('aria-busy'), false);
});

test('history restoration uses response input state rather than the previously focused query', async () => {
	const h = harness();
	h.document.activeElement = { name: 'q', tagName: 'INPUT', value: 'Workers', selectionStart: 4, selectionEnd: 4 };
	const next = h.success('D1');
	h.browser.location = new URL('https://catalog.example.com/catalog?q=D1');
	h.events.get('popstate')();
	h.requests[0].resolve(new Response('<html></html>', { headers: { 'Content-Type': 'text/html' } }));
	await settle();
	assert.equal(next.nextInput.value, 'D1');
	assert.equal(h.history.length, 0);
	assert.equal(h.status.textContent, '1 result');
});
