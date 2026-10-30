// Progressive enhancement of the same bounded SSR GET form, not a second search API.
export function searchUrl(form, origin, data = new FormData(form)) {
	const url = new URL(form.action, origin);
	url.search = new URLSearchParams(data).toString();
	url.searchParams.delete('page');
	return url;
}

export function enhanceCatalog(doc, browser) {
	let view = doc.querySelector('[data-catalog-view]');
	const status = doc.querySelector('[data-catalog-status]');
	if (!view || !status || !browser.fetch || !browser.history?.pushState) return;
	let timer,
		controller,
		generation = 0,
		composing = false,
		disabled = false,
		lastKind;
	const form = () => view.querySelector('form');
	const announce = (text) => {
		status.textContent = text;
	};
	function cancel() {
		browser.clearTimeout(timer);
		controller?.abort();
		generation++;
		view.removeAttribute('aria-busy');
	}
	async function update(url, kind) {
		cancel();
		const current = generation;
		const requestController = new AbortController();
		controller = requestController;
		const timeout = browser.setTimeout(() => requestController.abort(), 10_000);
		view.setAttribute('aria-busy', 'true');
		announce('Updating results…');
		try {
			if (url.origin !== browser.location.origin || url.pathname !== new URL(form().action).pathname)
				throw new Error('Unexpected search URL');
			const response = await browser.fetch(url, {
				headers: { Accept: 'text/html' },
				credentials: 'omit',
				redirect: 'error',
				signal: controller.signal,
			});
			if (!response.ok || !response.headers.get('Content-Type')?.startsWith('text/html')) throw new Error('Search unavailable');
			const next = new DOMParser().parseFromString(await response.text(), 'text/html');
			if (current !== generation) return;
			const nextView = next.querySelector('[data-catalog-view]');
			const canonical = next.querySelector('link[rel="canonical"]');
			if (!nextView || !canonical || !nextView.querySelector('[data-catalog-results]') || !nextView.querySelector('.results-count'))
				throw new Error('Incomplete search response');
			const effective = new URL(canonical.href);
			if (effective.pathname !== url.pathname) throw new Error('Unexpected canonical path');
			// Keep keyboard/caret, disclosure and scroll state while replacing only
			// trusted, escaped server-rendered HTML. No API data enters innerHTML.
			const active = view.contains(doc.activeElement) ? doc.activeElement : null;
			const name = active?.name;
			const selection = active?.tagName === 'INPUT' ? [active.selectionStart, active.selectionEnd] : null;
			const value = name === 'q' && kind !== 'history' ? active.value : null;
			const open = view.querySelector('details')?.open;
			const replacement = doc.importNode(nextView, true);
			if (replacement.querySelector('details')) replacement.querySelector('details').open = open;
			view.replaceWith(replacement);
			view = replacement;
			if (name) {
				const target = form().elements.namedItem(name);
				if (target) {
					if (value !== null) target.value = value;
					target.focus({ preventScroll: true });
					if (selection && selection[0] !== null) target.setSelectionRange(...selection);
				}
			} else if (active?.type === 'submit') form().querySelector('[type="submit"]')?.focus({ preventScroll: true });
			for (const selector of [
				'link[rel="canonical"]',
				'link[rel="alternate"][type="text/markdown"]',
				'meta[property="og:url"]',
				'script[type="application/ld+json"]',
			]) {
				const incoming = next.querySelector(selector),
					existing = doc.querySelector(selector);
				if (incoming && existing) existing.replaceWith(doc.importNode(incoming, true));
			}
			const markdown = next.querySelector('[data-markdown-link]');
			if (markdown) doc.querySelector('[data-markdown-link]')?.setAttribute('href', markdown.getAttribute('href'));
			doc.title = next.title;
			if (kind !== 'history') {
				const method = kind === 'typing' && lastKind === 'typing' ? 'replaceState' : 'pushState';
				const path = effective.pathname + effective.search;
				if (path !== browser.location.pathname + browser.location.search) browser.history[method](null, '', path);
			}
			lastKind = kind;
			announce(view.querySelector('.results-count').textContent.trim());
		} catch (error) {
			if (current !== generation) return;
			// Retain the form and last good results. The next Search uses native
			// navigation, rather than trapping the user in a broken enhancement.
			disabled = true;
			announce('Live update unavailable. Press Search to load your current filters.');
		} finally {
			browser.clearTimeout(timeout);
			if (current === generation) view.removeAttribute('aria-busy');
		}
	}
	function schedule() {
		cancel();
		if (!disabled && !composing)
			timer = browser.setTimeout(() => {
				void update(searchUrl(form(), browser.location.origin), 'typing');
			}, 350);
	}
	doc.addEventListener('input', (event) => {
		if (event.target.form === form() && event.target.name === 'q') {
			composing = event.isComposing;
			schedule();
		}
	});
	doc.addEventListener('compositionstart', (event) => {
		if (event.target.form === form()) {
			composing = true;
			cancel();
		}
	});
	doc.addEventListener('compositionend', (event) => {
		if (event.target.form === form()) {
			composing = false;
			schedule();
		}
	});
	doc.addEventListener('change', (event) => {
		if (!disabled && event.target.form === form() && event.target.tagName === 'SELECT')
			void update(searchUrl(form(), browser.location.origin), 'filter');
	});
	doc.addEventListener('submit', (event) => {
		if (event.target === form() && !disabled) {
			event.preventDefault();
			void update(searchUrl(form(), browser.location.origin), 'submit');
		}
	});
	browser.addEventListener('popstate', () => {
		if (disabled) browser.location.reload();
		else void update(new URL(browser.location.href), 'history');
	});
	browser.addEventListener('pagehide', cancel);
}

if (typeof document !== 'undefined') enhanceCatalog(document, window);
