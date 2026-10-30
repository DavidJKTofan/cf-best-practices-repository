// Keep long reading-page contents compact on small screens; all links remain in no-script HTML.
const contents = document.querySelector('.contents-disclosure');
if (contents instanceof HTMLDetailsElement) {
	const compact = matchMedia('(max-width: 900px)');
	const update = () => {
		contents.open = !compact.matches;
	};
	update();
	compact.addEventListener('change', update);
}
