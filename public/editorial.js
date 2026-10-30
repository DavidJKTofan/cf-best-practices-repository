import { template } from './editorial-templates.js';
import { createEditorialSubmission } from './editorial-retry.js';
const $ = (id) => document.getElementById(id);
const base = '/dashboard/api/catalog';
let id = null,
	version = 0,
	roles = [],
	phase = 'draft',
	page = 1,
	busy = false,
	dirty = false;
let storage;
try {
	storage = sessionStorage;
} catch {
	/* Storage is optional; never store private content. */
}
const submission = createEditorialSubmission(storage);
const say = (text) => {
	$('status').textContent = text;
};
function controls() {
	for (const button of document.querySelectorAll('button')) button.disabled = busy;
	$('save').disabled = busy || !roles.includes('editor');
	$('submit').disabled = busy || !id || dirty || phase !== 'draft' || !roles.includes('editor');
	for (const action of ['approve', 'changes'])
		$(action).disabled = busy || !id || dirty || phase !== 'in-review' || !roles.includes('reviewer');
	$('publish').disabled = busy || !id || dirty || phase !== 'approved' || !roles.includes('publisher');
}
async function get(path) {
	const response = await fetch(path, { cache: 'no-store', credentials: 'same-origin' });
	const body = await response.json();
	if (!response.ok || !body.success) {
		const error = new Error(body.error || `HTTP ${response.status}`);
		error.status = response.status;
		throw error;
	}
	return body;
}
async function run(action) {
	if (busy) return;
	busy = true;
	controls();
	try {
		await action();
	} catch (err) {
		say(`${err.message} No unsaved text was discarded. If a response was lost, retry unchanged data; do not create a new operation.`);
	} finally {
		busy = false;
		controls();
	}
}
function show(draft) {
	id = draft.practiceId;
	version = draft.version;
	phase = draft.status;
	dirty = false;
	$('entry-id').value = id ?? '';
	$('version').textContent = `${id ? `No. ${id}` : 'New'} / version ${version} / ${phase}`;
	$('envelope').value = JSON.stringify(draft.content, null, 2);
	$('lifecycle').value = draft.lifecycle.state;
	$('reason').value = draft.lifecycle.reason ?? '';
	$('replacement').value = draft.lifecycle.supersededBy ?? '';
	for (const [link, suffix] of [
		['preview', ''],
		['markdown', '?format=markdown'],
	]) {
		$(link).hidden = !id || !version;
		$(link).href = `${base}/${id}/preview${suffix}`;
	}
	controls();
}
async function queue() {
	const body = await get(`${base}?page=${page}`);
	roles = body.roles;
	$('roles').textContent = `Your roles: ${roles.join(', ')}`;
	$('queue').replaceChildren(
		...body.data.map((draft) => {
			const li = document.createElement('li'),
				button = document.createElement('button');
			button.textContent = `${draft.practiceId} · ${draft.title} / ${draft.status}`;
			button.addEventListener('click', () => run(() => open(draft.practiceId)));
			li.append(button);
			return li;
		}),
	);
}
async function open(target) {
	if (dirty && !confirm('Discard unsaved edits and load this working copy?')) return;
	try {
		show((await get(`${base}/${target}/draft`)).data);
	} catch (err) {
		if (err.status !== 404) throw err;
		// A native public entry without a draft can start a new reviewed revision.
		const entry = (await get(`/api/v2/entries/${target}`)).data;
		if (entry.schemaVersion !== 1) throw new Error('Legacy conversion is intentionally blocked. Use legacy authoring for new v1 entries.');
		const keys = Object.keys(template(entry.type));
		show({
			practiceId: target,
			version: 0,
			status: 'draft',
			content: Object.fromEntries(keys.map((key) => [key, entry[key]])),
			lifecycle: entry.lifecycle,
		});
	}
	say('Loaded saved copy. Preview and review always use server-saved content.');
}
async function mutate(path, method, body) {
	const serialized = JSON.stringify(body);
	const key = await submission.key(path, method, serialized, () =>
		confirm(
			'An earlier operation is unresolved and may already have committed. Check the saved copies first. Starting a new operation can create a duplicate. Continue with a new key?',
		),
	);
	if (!key) return;
	const response = await fetch(path, {
		method,
		credentials: 'same-origin',
		headers: { 'Content-Type': 'application/json', 'Idempotency-Key': key },
		body: serialized,
	});
	const result = await response.json();
	if (!response.ok || !result.success) throw new Error(result.error || `HTTP ${response.status}`);
	// A confirmed creation must immediately target its returned ID, even if the
	// following refresh fails. Otherwise the Save button could create a duplicate.
	id = result.data.practiceId;
	version = result.data.version;
	phase = 'refresh-required';
	dirty = false;
	$('entry-id').value = id;
	$('version').textContent = `No. ${id} / version ${version} / saved; refresh required`;
	submission.complete();
	const saved = await get(`${base}/${result.data.practiceId}/draft`);
	show(saved.data);
	await queue();
	say(
		`Saved version ${result.data.version}. ${result.data.purge ? 'Publication committed; cache purge attempted. Browser caches may still be fresh.' : 'Public guidance is unchanged.'}`,
	);
}
$('editor').addEventListener('input', () => {
	dirty = true;
	controls();
});
$('editor').addEventListener('submit', (event) => {
	event.preventDefault();
	void run(async () => {
		const lifecycle = {
			state: $('lifecycle').value,
			reason: $('lifecycle').value === 'active' ? null : $('reason').value,
			supersededBy: $('lifecycle').value === 'superseded' ? Number($('replacement').value) : null,
		};
		await mutate(id ? `${base}/${id}/draft` : base, id ? 'PUT' : 'POST', {
			...(id ? { expectedVersion: version } : {}),
			content: JSON.parse($('envelope').value),
			lifecycle,
		});
	});
});
$('open').addEventListener('submit', (event) => {
	event.preventDefault();
	void run(() => open(Number($('entry-id').value)));
});
$('new').addEventListener('click', () => {
	if (dirty && !confirm('Discard unsaved edits?')) return;
	show({
		practiceId: null,
		version: 0,
		status: 'draft',
		content: template($('content-type').value),
		lifecycle: { state: 'active', reason: null, supersededBy: null },
	});
	say('New private scaffold. Replace all placeholders; schema validity is not factual review.');
});
for (const [button, action, decision] of [
	['submit', 'submit'],
	['approve', 'review', 'approve'],
	['changes', 'review', 'request-changes'],
	['publish', 'publish'],
])
	$(button).addEventListener('click', () => {
		void run(async () => {
			if (action === 'publish' && !confirm(`Publish reviewed saved version ${version} of entry ${id}? This changes public guidance.`))
				return;
			await mutate(`${base}/${id}/${action}`, 'POST', { expectedVersion: version, ...(decision ? { decision } : {}) });
		});
	});
$('refresh').addEventListener('click', () => {
	void run(queue);
});
$('previous').addEventListener('click', () => {
	page = Math.max(1, page - 1);
	void run(queue);
});
$('next').addEventListener('click', () => {
	page = Math.min(10000, page + 1);
	void run(queue);
});
window.addEventListener('beforeunload', (event) => {
	if (dirty) {
		event.preventDefault();
		event.returnValue = '';
	}
});
show({
	practiceId: null,
	version: 0,
	status: 'draft',
	content: template('recommendation'),
	lifecycle: { state: 'active', reason: null, supersededBy: null },
});
void run(async () => {
	await queue();
	say('Access verified. Select a saved copy or begin a new typed draft.');
});
