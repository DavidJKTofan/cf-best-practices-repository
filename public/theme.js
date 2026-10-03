// public/theme.js — light/dark toggle. The initial theme is applied by an inline <head> script to avoid a flash.
const root = document.documentElement;
const button = document.querySelector('.theme-switch');
const systemDark = matchMedia('(prefers-color-scheme: dark)');

function savedTheme() {
	try {
		return localStorage.getItem('theme');
	} catch {
		return null;
	}
}

function apply(theme) {
	root.dataset.theme = theme;
	button?.setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
	button?.setAttribute('title', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
}

apply(root.dataset.theme === 'dark' ? 'dark' : 'light');

button?.addEventListener('click', () => {
	const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
	apply(next);
	try {
		localStorage.setItem('theme', next);
	} catch {}
});

// Follow OS changes until the user picks a theme explicitly
systemDark.addEventListener('change', (event) => {
	if (!savedTheme()) apply(event.matches ? 'dark' : 'light');
});
