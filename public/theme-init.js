// Apply the preference before styles paint; shared by the catalog and practice pages.
(() => {
	let theme;
	try {
		theme = localStorage.getItem('theme');
	} catch {}
	if (theme !== 'light' && theme !== 'dark') theme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
	document.documentElement.dataset.theme = theme;
})();
