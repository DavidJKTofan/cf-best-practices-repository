// public/dashboard.js — form for adding a practice (page and write API are protected by Cloudflare Access)
import { createSubmission } from './practice-submission.js';

const WRITE_URL = '/dashboard/api/practices';

const form = document.getElementById('practice-form');
const status = document.getElementById('status');
const submitButton = form.querySelector('button[type="submit"]');
let storage;
try {
	storage = window.sessionStorage;
} catch (err) {
	console.error(err);
}
const submission = createSubmission(storage);
let resettingAfterSave = false;

function showStatus(type, ...content) {
	const alert = document.createElement('div');
	alert.className = `alert alert-${type}`;
	if (type === 'error') alert.setAttribute('role', 'alert');
	alert.append(...content);
	status.replaceChildren(alert);
	alert.scrollIntoView({ block: 'nearest' });
}

async function loadOptions(url, select, placeholder) {
	const response = await fetch(url);
	const body = await response.json();
	if (!response.ok || !body.success) throw new Error(body.error || `HTTP ${response.status}`);
	select.replaceChildren(new Option(placeholder, ''), ...body.data.map((item) => new Option(item.name, item.id)));
}

async function initialize() {
	try {
		await Promise.all([
			loadOptions('/api/categories', form.elements.category_id, 'Select category'),
			loadOptions('/api/features', form.elements.feature_id, 'Select feature'),
		]);
	} catch (error) {
		console.error('Failed to load categories/features', error);
		showStatus('error', 'Could not load categories and features. Reload the page to try again.');
	}
}

form.addEventListener('submit', async (event) => {
	event.preventDefault();
	if (submitButton.disabled) return;

	submitButton.disabled = true;
	submitButton.setAttribute('aria-busy', 'true');
	status.replaceChildren();

	try {
		const response = await fetch(WRITE_URL, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'Idempotency-Key': submission.key() },
			body: JSON.stringify(Object.fromEntries(new FormData(form))),
		});

		let result;
		try {
			result = await response.json();
		} catch {
			throw new Error(
				`Unexpected response from the server (HTTP ${response.status}). Your Access session may have expired; reload the page.`,
			);
		}
		if (!response.ok || !result.success) throw new Error(result.error || `HTTP ${response.status}`);

		submission.complete();
		resettingAfterSave = true;
		form.reset(); // before showStatus: the reset handler clears the status area
		resettingAfterSave = false;
		const link = document.createElement('a');
		link.href = `/practices/${result.id}`;
		link.textContent = 'View it in the repository';
		showStatus('success', 'Practice saved. ', link);

		// Best effort for this browser's API cache, not a guarantee of immediate global freshness.
		void fetch('/api/practices', { cache: 'reload' }).catch((err) => console.error(err));
	} catch (error) {
		console.error('Failed to save practice', error);
		// A TypeError here usually means Access redirected the request to its login page (session expired)
		const message =
			error instanceof TypeError
				? 'Could not reach the server. If your Access session expired, reload the page to sign in again.'
				: error.message;
		showStatus('error', `Could not confirm the save: ${message} Retry with the same form data; the retry key is retained in this tab.`);
	} finally {
		submitButton.disabled = false;
		submitButton.removeAttribute('aria-busy');
	}
});

form.addEventListener('reset', (event) => {
	if (!resettingAfterSave && submitButton.disabled) {
		event.preventDefault();
		return;
	}
	if (!resettingAfterSave && submission.pending()) {
		if (
			!window.confirm(
				'A previous save may have completed. Check the repository before starting over, which can create another practice. Start a new submission?',
			)
		) {
			event.preventDefault();
			return;
		}
		submission.complete();
	}
	status.replaceChildren();
});

void initialize();
