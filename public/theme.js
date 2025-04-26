// Add theme switcher logic at the top of the file
const themeSwitch = document.querySelector('.theme-switch');
const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');

// Load saved theme or use system preference
const savedTheme = localStorage.getItem('theme');
if (savedTheme) {
	document.documentElement.dataset.theme = savedTheme;
} else if (prefersDarkScheme.matches) {
	document.documentElement.dataset.theme = 'dark';
}

// Update icon based on current theme
function updateThemeIcon() {
	const isDark = document.documentElement.dataset.theme === 'dark';
	themeSwitch.querySelector('.sun').style.display = isDark ? 'none' : 'block';
	themeSwitch.querySelector('.moon').style.display = isDark ? 'block' : 'none';
}

// Toggle theme
themeSwitch.addEventListener('click', () => {
	const currentTheme = document.documentElement.dataset.theme;
	const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
	document.documentElement.dataset.theme = newTheme;
	localStorage.setItem('theme', newTheme);
	updateThemeIcon();
});

// Initialize icon state
updateThemeIcon();
