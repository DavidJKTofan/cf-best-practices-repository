// public/dashboard.js — form for adding a practice (page and write API are protected by Cloudflare Access)

const WRITE_URL = '/dashboard/api/practices';

const form = document.getElementById('practice-form');
const status = document.getElementById('status');
const submitButton = form.querySelector('button[type="submit"]');

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
			headers: { 'Content-Type': 'application/json' },
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

		form.reset(); // before showStatus: the reset handler clears the status area
		const link = document.createElement('a');
		link.href = `/#practice-${result.id}`;
		link.textContent = 'View it in the repository';
		showStatus('success', 'Practice saved. ', link);

		// Refresh the browser's cached copy so the repository page shows the new entry right away
		fetch('/api/practices', { cache: 'reload' }).catch(() => {});
	} catch (error) {
		console.error('Failed to save practice', error);
		// A TypeError here usually means Access redirected the request to its login page (session expired)
		const message =
			error instanceof TypeError
				? 'Could not reach the server. If your Access session expired, reload the page to sign in again.'
				: error.message;
		showStatus('error', `Could not save the practice: ${message}`);
	} finally {
		submitButton.disabled = false;
		submitButton.removeAttribute('aria-busy');
	}
});

form.addEventListener('reset', () => status.replaceChildren());

initialize();
