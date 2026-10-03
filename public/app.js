// public/app.js — loads all practices once, then searches, filters, and sorts them client-side.

const API_URL = '/api/practices'; // must match the <link rel="preload"> in index.html

const els = {
	search: document.getElementById('search'),
	filters: document.getElementById('filters'),
	filtersToggle: document.querySelector('.filters-toggle'),
	filterCount: document.querySelector('.filter-count'),
	reset: document.getElementById('reset'),
	summary: document.getElementById('summary'),
	toggleAll: document.getElementById('toggle-all'),
	rows: document.getElementById('rows'),
	toolbar: document.querySelector('.toolbar'),
	header: document.querySelector('.site-header'),
	backToTop: document.getElementById('back-to-top'),
	sortButtons: document.querySelectorAll('th [data-sort]'),
};

const COLUMN_COUNT = 7;

// Semantic sort orders; anything unknown (or unset) sorts last
const RANK = {
	level: ['Mandatory', 'Recommended', 'Optional', 'Situational'],
	impact: ['High', 'Medium', 'Low'],
	difficulty: ['Easy', 'Medium', 'Complex'],
};

// URL param -> how to read the value from a practice, and how to label it in the <select>
const FILTERS = {
	category: { value: (p) => p.category_id, label: (p) => p.category_name, order: 'alpha' },
	feature: { value: (p) => p.feature_id, label: (p) => p.feature_name, order: 'alpha' },
	domain: { value: (p) => p.domain, label: (p) => p.domain, order: 'alpha' },
	level: { value: (p) => p.recommendation_level, label: (p) => p.recommendation_level, order: 'rank' },
	impact: { value: (p) => p.impact_level, label: (p) => `${p.impact_level} impact`, order: 'rank' },
	difficulty: { value: (p) => p.difficulty_level, label: (p) => p.difficulty_level, order: 'rank' },
};

// Sort keys; null means "no value" and always sorts last, in either direction
const SORTS = {
	title: (p) => p.title,
	category: (p) => p.category_name,
	domain: (p) => p.domain,
	level: (p) => p.recommendation_level && rank('level', p.recommendation_level),
	impact: (p) => p.impact_level && rank('impact', p.impact_level),
	difficulty: (p) => p.difficulty_level && rank('difficulty', p.difficulty_level),
	feature: (p) => p.feature_name,
};

const state = {
	practices: [],
	query: '',
	filters: {},
	sort: null,
	dir: 'asc',
	expanded: new Set(),
};

const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

function rank(kind, value) {
	const index = RANK[kind].indexOf(value);
	return index === -1 ? RANK[kind].length : index;
}

function debounce(fn, ms) {
	let timer;
	return (...args) => {
		clearTimeout(timer);
		timer = setTimeout(() => fn(...args), ms);
	};
}

function el(tag, props = {}, ...children) {
	const node = document.createElement(tag);
	for (const [key, value] of Object.entries(props)) {
		if (value === undefined || value === null || value === false) continue;
		if (key === 'className') node.className = value;
		else if (key === 'dataset') Object.assign(node.dataset, value);
		else if (key in node && typeof value !== 'string') node[key] = value;
		else node.setAttribute(key, value === true ? '' : value);
	}
	node.append(...children.filter((c) => c !== null && c !== undefined && c !== false));
	return node;
}

// A muted dash that screen readers announce as "Not rated"
function notRated() {
	return el(
		'span',
		{ className: 'muted' },
		el('span', { 'aria-hidden': 'true' }, '—'),
		el('span', { className: 'visually-hidden' }, 'Not rated'),
	);
}

function slug(value) {
	return String(value ?? 'none')
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-');
}

// --- Search ---------------------------------------------------------------------------------------

function searchTerms(query) {
	return query.toLowerCase().split(/\s+/).filter(Boolean);
}

function buildSearchIndex(p) {
	return [
		p.title,
		p.description,
		p.prerequisites,
		p.expressions_configuration_details,
		p.notes,
		p.category_name,
		p.feature_name,
		p.domain,
		p.recommendation_level,
	]
		.filter(Boolean)
		.join('\n')
		.toLowerCase();
}

function escapeRegExp(text) {
	return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Returns text with search matches wrapped in <mark>, built from text nodes (never innerHTML)
function highlight(text, terms) {
	if (!text || terms.length === 0) return document.createTextNode(text ?? '');
	const pattern = new RegExp(`(${terms.map(escapeRegExp).join('|')})`, 'gi');
	const fragment = document.createDocumentFragment();
	text.split(pattern).forEach((part, i) => {
		if (part) fragment.append(i % 2 ? el('mark', {}, part) : part);
	});
	return fragment;
}

// --- Filtering & sorting --------------------------------------------------------------------------

function visiblePractices() {
	const terms = searchTerms(state.query);
	const active = Object.entries(state.filters).filter(([, value]) => value);

	const matches = state.practices.filter(
		(p) =>
			terms.every((term) => p._search.includes(term)) && active.every(([param, value]) => String(FILTERS[param].value(p) ?? '') === value),
	);

	if (!state.sort) return matches;
	const key = SORTS[state.sort];
	const direction = state.dir === 'desc' ? -1 : 1;
	return matches.sort((a, b) => {
		const x = key(a) ?? null;
		const y = key(b) ?? null;
		if (x === null || y === null) return (x === null) - (y === null) || collator.compare(a.title, b.title);
		const result = typeof x === 'number' && typeof y === 'number' ? x - y : collator.compare(x, y);
		return result * direction || collator.compare(a.title, b.title);
	});
}

function populateFilters() {
	for (const [param, config] of Object.entries(FILTERS)) {
		const select = els.filters.querySelector(`[data-filter="${param}"]`);
		const options = new Map();
		for (const p of state.practices) {
			const value = config.value(p);
			if (value !== null && value !== undefined && value !== '') options.set(String(value), config.label(p));
		}

		const sorted = [...options].sort(([va, la], [vb, lb]) =>
			config.order === 'alpha' ? collator.compare(la, lb) : rank(param, va) - rank(param, vb) || collator.compare(la, lb),
		);
		select.append(...sorted.map(([value, label]) => new Option(label, value)));
	}
}

// --- Rendering ------------------------------------------------------------------------------------

function renderRow(p, terms) {
	const id = p.practice_id;
	const expanded = state.expanded.has(id);

	return el(
		'tr',
		{ id: `practice-${id}`, className: expanded ? 'row is-expanded' : 'row', dataset: { id } },
		el(
			'td',
			{ className: 'col-title' },
			el(
				'button',
				{
					type: 'button',
					className: 'row-toggle',
					'aria-expanded': String(expanded),
					'aria-controls': `detail-${id}`,
				},
				highlight(p.title, terms),
			),
			el('p', { className: 'desc' }, highlight(p.description, terms)),
		),
		el('td', { className: 'col-category', dataset: { label: 'Category' } }, p.category_name ?? '—'),
		el('td', { className: 'col-domain' }, el('span', { className: `badge domain-${slug(p.domain)}` }, p.domain)),
		el('td', { className: `col-level level-${slug(p.recommendation_level)}` }, p.recommendation_level ?? '—'),
		el('td', { className: `col-impact meter impact-${slug(p.impact_level)}`, dataset: { label: 'Impact' } }, p.impact_level ?? notRated()),
		el(
			'td',
			{ className: `col-difficulty meter difficulty-${slug(p.difficulty_level)}`, dataset: { label: 'Difficulty' } },
			p.difficulty_level ?? notRated(),
		),
		el(
			'td',
			{ className: 'col-feature' },
			p.feature_url
				? el('a', { href: p.feature_url, target: '_blank', rel: 'noopener noreferrer' }, p.feature_name)
				: (p.feature_name ?? '—'),
		),
	);
}

function detailItem(label, content) {
	return content ? el('div', { className: 'detail-item' }, el('dt', {}, label), el('dd', {}, content)) : null;
}

function renderDetail(p, terms) {
	const id = p.practice_id;
	const config = p.expressions_configuration_details;
	const source = p.source_reference?.startsWith('https://') ? p.source_reference : null;
	const updated = p.updated_at ? new Date(`${p.updated_at.replace(' ', 'T')}Z`) : null;

	const code = config
		? el(
				'div',
				{ className: 'code-block' },
				el('pre', { tabIndex: 0, 'aria-label': 'Configuration or expression' }, el('code', {}, highlight(config, terms))),
				el('button', { type: 'button', className: 'btn btn-small copy-btn', dataset: { copy: config } }, 'Copy'),
			)
		: null;

	return el(
		'tr',
		{ id: `detail-${id}`, className: 'detail' },
		el(
			'td',
			{ colSpan: COLUMN_COUNT },
			el(
				'dl',
				{ className: 'detail-grid' },
				detailItem('Description', highlight(p.description, terms)),
				detailItem('Prerequisites', p.prerequisites && highlight(p.prerequisites, terms)),
				detailItem('Notes', p.notes && highlight(p.notes, terms)),
				code && el('div', { className: 'detail-item detail-code' }, el('dt', {}, 'Configuration / expression'), el('dd', {}, code)),
			),
			el(
				'p',
				{ className: 'detail-meta' },
				source && el('a', { href: source, target: '_blank', rel: 'noopener noreferrer' }, 'Source documentation'),
				p.feature_url && el('a', { href: p.feature_url, target: '_blank', rel: 'noopener noreferrer' }, `${p.feature_name} docs`),
				el('a', { href: `#practice-${id}` }, 'Permalink'),
				updated && !Number.isNaN(updated.getTime())
					? el('span', {}, 'Updated ', el('time', { dateTime: updated.toISOString() }, updated.toLocaleDateString()))
					: null,
			),
		),
	);
}

function render() {
	const practices = visiblePractices();
	const terms = searchTerms(state.query);
	const fragment = document.createDocumentFragment();

	for (const p of practices) {
		fragment.append(renderRow(p, terms));
		if (state.expanded.has(p.practice_id)) fragment.append(renderDetail(p, terms));
	}

	if (practices.length === 0) {
		fragment.append(
			el(
				'tr',
				{ className: 'state-row' },
				el(
					'td',
					{ colSpan: COLUMN_COUNT },
					el(
						'div',
						{ className: 'state' },
						el('p', {}, 'No practices match your search and filters.'),
						el('button', { type: 'button', className: 'btn', dataset: { action: 'reset' } }, 'Clear search and filters'),
					),
				),
			),
		);
	}

	els.rows.replaceChildren(fragment);
	els.rows.removeAttribute('aria-busy');
	updateChrome(practices);
	syncUrl();
}

function updateChrome(practices) {
	const total = state.practices.length;
	const activeFilters = Object.values(state.filters).filter(Boolean).length;
	const filtered = activeFilters > 0 || state.query.trim() !== '';

	els.summary.textContent = filtered ? `Showing ${practices.length} of ${total} practices` : `${total} practice${total === 1 ? '' : 's'}`;

	els.filterCount.hidden = activeFilters === 0;
	els.filterCount.textContent = activeFilters;
	els.reset.disabled = !filtered && !state.sort;

	const allExpanded = practices.length > 0 && practices.every((p) => state.expanded.has(p.practice_id));
	els.toggleAll.disabled = practices.length === 0;
	els.toggleAll.textContent = allExpanded ? 'Collapse all' : 'Expand all';
	els.toggleAll.dataset.mode = allExpanded ? 'collapse' : 'expand';

	for (const button of els.sortButtons) {
		const th = button.closest('th');
		th.setAttribute('aria-sort', button.dataset.sort === state.sort ? (state.dir === 'asc' ? 'ascending' : 'descending') : 'none');
	}
}

function toggleRow(id, force) {
	const practice = state.practices.find((p) => p.practice_id === id);
	const row = document.getElementById(`practice-${id}`);
	if (!practice || !row) return;

	const expand = force ?? !state.expanded.has(id);
	if (expand === state.expanded.has(id)) return;

	if (expand) {
		state.expanded.add(id);
		row.after(renderDetail(practice, searchTerms(state.query)));
	} else {
		state.expanded.delete(id);
		document.getElementById(`detail-${id}`)?.remove();
	}
	row.classList.toggle('is-expanded', expand);
	row.querySelector('.row-toggle').setAttribute('aria-expanded', String(expand));
}

// --- URL state (shareable, back/forward friendly) -------------------------------------------------

function syncUrl() {
	const params = new URLSearchParams();
	if (state.query.trim()) params.set('q', state.query.trim());
	for (const [param, value] of Object.entries(state.filters)) if (value) params.set(param, value);
	if (state.sort) {
		params.set('sort', state.sort);
		if (state.dir === 'desc') params.set('dir', 'desc');
	}
	const query = params.toString();
	const url = `${location.pathname}${query ? `?${query}` : ''}${location.hash}`;
	if (url !== `${location.pathname}${location.search}${location.hash}`) history.replaceState(null, '', url);
}

function readUrl() {
	const params = new URLSearchParams(location.search);
	state.query = params.get('q') ?? '';
	els.search.value = state.query;

	for (const select of els.filters.querySelectorAll('select[data-filter]')) {
		const value = params.get(select.dataset.filter) ?? '';
		// Ignore values that no longer exist in the data
		select.value = [...select.options].some((o) => o.value === value) ? value : '';
		state.filters[select.dataset.filter] = select.value;
		select.classList.toggle('is-active', select.value !== '');
	}

	const sort = params.get('sort');
	state.sort = sort in SORTS ? sort : null;
	state.dir = params.get('dir') === 'desc' ? 'desc' : 'asc';
}

function syncToolbarHeight() {
	document.documentElement.style.setProperty('--toolbar-h', `${els.toolbar.offsetHeight}px`);
}

function openFromHash() {
	const match = /^#practice-(\d+)$/.exec(location.hash);
	if (!match) return;
	const id = Number(match[1]);
	toggleRow(id, true);

	const scroll = () => {
		syncToolbarHeight(); // scroll-margin depends on it, and ResizeObserver may not have fired yet
		document.getElementById(`practice-${id}`)?.scrollIntoView({ block: 'start' });
	};
	// While the page is loading, the browser's own fragment scrolling would override ours
	if (document.readyState === 'complete') scroll();
	else addEventListener('load', () => requestAnimationFrame(scroll), { once: true });
}

function resetAll() {
	state.query = '';
	state.sort = null;
	state.dir = 'asc';
	els.search.value = '';
	for (const select of els.filters.querySelectorAll('select[data-filter]')) {
		select.value = '';
		select.classList.remove('is-active');
		state.filters[select.dataset.filter] = '';
	}
	render();
}

// --- Data loading ---------------------------------------------------------------------------------

async function fetchPractices() {
	const response = await fetch(API_URL);
	let body;
	try {
		body = await response.json();
	} catch {
		throw new Error(`Unexpected response (HTTP ${response.status})`);
	}
	if (!response.ok || !body.success) throw new Error(body.error || `HTTP ${response.status}`);
	return body.data;
}

function renderError(message) {
	els.summary.textContent = 'Could not load practices';
	els.rows.removeAttribute('aria-busy');
	els.rows.replaceChildren(
		el(
			'tr',
			{ className: 'state-row' },
			el(
				'td',
				{ colSpan: COLUMN_COUNT },
				el(
					'div',
					{ className: 'state state-error', role: 'alert' },
					el('p', {}, `Failed to load best practices: ${message}`),
					el('button', { type: 'button', className: 'btn', dataset: { action: 'retry' } }, 'Try again'),
				),
			),
		),
	);
}

async function load() {
	try {
		const practices = await fetchPractices();
		state.practices = practices.map((p) => ({ ...p, _search: buildSearchIndex(p) }));
		populateFilters();
		readUrl();
		render();
		openFromHash();
	} catch (error) {
		console.error('Failed to load practices', error);
		renderError(error.message);
	}
}

// --- Events ---------------------------------------------------------------------------------------

const onSearch = debounce(() => {
	state.query = els.search.value;
	render();
}, 120);

els.search.addEventListener('input', onSearch);
els.search.addEventListener('keydown', (event) => {
	if (event.key === 'Escape' && els.search.value) {
		event.preventDefault();
		els.search.value = '';
		state.query = '';
		render();
	}
});

els.filters.addEventListener('change', (event) => {
	const select = event.target.closest('select[data-filter]');
	if (!select) return;
	state.filters[select.dataset.filter] = select.value;
	select.classList.toggle('is-active', select.value !== '');
	render();
});

els.reset.addEventListener('click', resetAll);

els.filtersToggle.addEventListener('click', () => {
	const expanded = els.filtersToggle.getAttribute('aria-expanded') !== 'true';
	els.filtersToggle.setAttribute('aria-expanded', String(expanded));
});

els.toggleAll.addEventListener('click', () => {
	const expand = els.toggleAll.dataset.mode !== 'collapse';
	for (const p of visiblePractices()) {
		if (expand) state.expanded.add(p.practice_id);
		else state.expanded.delete(p.practice_id);
	}
	render();
});

for (const button of els.sortButtons) {
	button.addEventListener('click', () => {
		const key = button.dataset.sort;
		state.dir = state.sort === key && state.dir === 'asc' ? 'desc' : 'asc';
		state.sort = key;
		render();
	});
}

els.rows.addEventListener('click', async (event) => {
	const action = event.target.closest('[data-action]')?.dataset.action;
	if (action === 'reset') return resetAll();
	if (action === 'retry') {
		els.summary.textContent = 'Loading practices…';
		return load();
	}

	const copyButton = event.target.closest('.copy-btn');
	if (copyButton) {
		try {
			await navigator.clipboard.writeText(copyButton.dataset.copy);
			copyButton.textContent = 'Copied';
		} catch {
			copyButton.textContent = 'Copy failed';
		}
		setTimeout(() => (copyButton.textContent = 'Copy'), 1500);
		return;
	}

	// Clicking anywhere on a row (except links) toggles its details
	const row = event.target.closest('tr.row');
	if (!row || event.target.closest('a')) return;
	if (!event.target.closest('.row-toggle') && window.getSelection()?.toString()) return; // allow text selection
	toggleRow(Number(row.dataset.id));
});

window.addEventListener('hashchange', openFromHash);

document.addEventListener('keydown', (event) => {
	const typing = event.target.closest('input, textarea, select, [contenteditable]');
	if ((event.key === '/' && !typing) || ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k')) {
		event.preventDefault();
		els.search.focus();
		els.search.select();
	}
});

// Keep the sticky table header just below the sticky toolbar, whatever its height
new ResizeObserver(syncToolbarHeight).observe(els.toolbar);

// Show "back to top" once the page header has scrolled out of view
new IntersectionObserver(([entry]) => {
	els.backToTop.hidden = entry.isIntersecting;
}).observe(els.header);

els.backToTop.addEventListener('click', () => {
	window.scrollTo({ top: 0, behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
	els.search.focus({ preventScroll: true });
});

load();
