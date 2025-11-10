// public/app.js - Enhanced with better UX

const API_BASE = '/api';

// DOM Elements
const tableBody = document.getElementById('practicesTableBody');
const searchInput = document.getElementById('searchInput');
const categoryFilter = document.getElementById('categoryFilter');
const featureFilter = document.getElementById('featureFilter');
const areaFilter = document.getElementById('areaFilter');
const levelFilter = document.getElementById('levelFilter');
const impactFilter = document.getElementById('impactFilter');
const resetFiltersButton = document.getElementById('resetFilters');
const errorMessage = document.getElementById('errorMessage');
const resultsCount = document.getElementById('resultsCount');
const filtersToggle = document.querySelector('.filters-toggle');
const filtersWrapper = document.getElementById('filters-wrapper');
const backToTopButton = document.getElementById('backToTop');

// State
let currentPractices = [];
let isLoading = false;

// --- Helper Functions ---

function updateResultsCount(count) {
	if (!resultsCount) return;

	if (count === 0) {
		resultsCount.textContent = 'No results found';
	} else if (count === 1) {
		resultsCount.textContent = '1 practice found';
	} else {
		resultsCount.textContent = `${count} practices found`;
	}
}

function displayError(message) {
	console.error('Error:', message);
	errorMessage.textContent = `⚠️ Error: ${message}. Please try refreshing.`;
	errorMessage.style.display = 'block';

	if (tableBody) {
		renderEmptyState('Failed to load data. Please try again.');
	}
}

function clearError() {
	errorMessage.textContent = '';
	errorMessage.style.display = 'none';
}

function renderLoadingState() {
	if (!tableBody) return;

	tableBody.innerHTML = `
		<tr>
			<td colspan="12">
				<div class="loading-state">
					<div class="spinner" role="status" aria-label="Loading"></div>
					<p>Loading practices...</p>
				</div>
			</td>
		</tr>
	`;
}

function renderEmptyState(message = 'No practices found matching your criteria.') {
	if (!tableBody) return;

	tableBody.innerHTML = `
		<tr>
			<td colspan="12">
				<div class="empty-state">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
						<circle cx="11" cy="11" r="8"></circle>
						<path d="m21 21-4.35-4.35"></path>
					</svg>
					<p>${message}</p>
				</div>
			</td>
		</tr>
	`;
}

// --- Fetch Data ---
async function fetchData(url) {
	try {
		const response = await fetch(url);

		if (!response.ok) {
			let errorMsg = `HTTP ${response.status}`;

			try {
				const errData = await response.json();
				errorMsg = errData.error || errorMsg;
			} catch (e) {
				// Response wasn't JSON
			}

			throw new Error(errorMsg);
		}

		const result = await response.json();

		if (!result.success) {
			throw new Error(result.error || 'API returned an error');
		}

		return result.data;
	} catch (error) {
		displayError(error.message);
		return null;
	}
}

// --- Render Table ---
function renderTable(practices) {
	if (!tableBody) return;
	clearError();

	currentPractices = practices || [];
	updateResultsCount(currentPractices.length);

	if (!practices || practices.length === 0) {
		renderEmptyState();
		return;
	}

	tableBody.innerHTML = '';

	practices.forEach((p) => {
		const tr = document.createElement('tr');
		tr.className = 'fade-in';

		const createCell = (label, content, isCode = false) => {
			const td = document.createElement('td');
			td.setAttribute('data-label', label);

			if (isCode && content) {
				const code = document.createElement('code');
				code.textContent = content;
				td.appendChild(code);
			} else {
				td.textContent = content || 'N/A';
			}

			return td;
		};

		const createLinkCell = (label, text, url) => {
			const td = document.createElement('td');
			td.setAttribute('data-label', label);

			if (url) {
				const a = document.createElement('a');
				a.href = url;
				a.textContent = text || 'Link';
				a.target = '_blank';
				a.rel = 'noopener noreferrer';
				td.appendChild(a);
			} else {
				td.textContent = text || 'N/A';
			}

			return td;
		};

		// Add cells to the row
		tr.appendChild(createCell('Title', p.title));
		tr.appendChild(createCell('Category', p.category_name));
		tr.appendChild(createCell('Domain', p.domain));
		tr.appendChild(createCell('Level', p.recommendation_level));
		tr.appendChild(createCell('Impact', p.impact_level));
		tr.appendChild(createCell('Difficulty', p.difficulty_level));
		tr.appendChild(createCell('Description', p.description));
		tr.appendChild(createCell('Prerequisites', p.prerequisites));
		tr.appendChild(createLinkCell('Feature', p.feature_name, p.feature_url));
		tr.appendChild(createCell('Configuration', p.expressions_configuration_details, true));
		tr.appendChild(
			createLinkCell(
				'Source',
				p.source_reference?.startsWith('https://') ? 'Documentation' : p.source_reference,
				p.source_reference?.startsWith('https://') ? p.source_reference : null
			)
		);
		tr.appendChild(createCell('Notes', p.notes || ''));

		tableBody.appendChild(tr);
	});
}

// --- Populate Select Dropdowns ---
function populateSelect(selectElement, items, defaultOptionText) {
	if (!selectElement) return;

	selectElement.innerHTML = `<option value="">${defaultOptionText}</option>`;

	items.forEach((item) => {
		const option = document.createElement('option');
		option.value = item.id;
		option.textContent = item.name;
		selectElement.appendChild(option);
	});
}

// --- Load Practices ---
async function loadPractices() {
	if (!tableBody || isLoading) return;

	isLoading = true;
	renderLoadingState();

	const params = new URLSearchParams();
	const searchTerm = searchInput.value.trim();
	const selectedCategoryId = categoryFilter.value;
	const selectedFeatureId = featureFilter.value;
	const selectedArea = areaFilter.value;
	const selectedLevel = levelFilter.value;
	const selectedImpact = impactFilter.value;

	if (searchTerm) params.append('search', searchTerm);
	if (selectedCategoryId) params.append('categoryId', selectedCategoryId);
	if (selectedFeatureId) params.append('featureId', selectedFeatureId);
	if (selectedArea) params.append('area', selectedArea);
	if (selectedLevel) params.append('level', selectedLevel);
	if (selectedImpact) params.append('impact', selectedImpact);

	const practices = await fetchData(`${API_BASE}/practices?${params.toString()}`);

	isLoading = false;

	if (practices !== null) {
		renderTable(practices);
	}
}

// --- Reset Filters ---
function resetAllFilters() {
	searchInput.value = '';
	categoryFilter.value = '';
	featureFilter.value = '';
	areaFilter.value = '';
	levelFilter.value = '';
	impactFilter.value = '';
	loadPractices();
}

// --- Mobile Filters Toggle ---
function toggleFilters() {
	const isExpanded = filtersToggle.getAttribute('aria-expanded') === 'true';
	const newState = !isExpanded;

	filtersToggle.setAttribute('aria-expanded', newState);

	if (newState) {
		filtersWrapper.classList.remove('collapsed');
	} else {
		filtersWrapper.classList.add('collapsed');
	}
}

// --- Back to Top ---
function handleScroll() {
	if (window.scrollY > 300) {
		backToTopButton?.classList.add('visible');
	} else {
		backToTopButton?.classList.remove('visible');
	}
}

function scrollToTop() {
	window.scrollTo({
		top: 0,
		behavior: 'smooth',
	});
}

// --- Debounce Function ---
function debounce(func, wait) {
	let timeout;
	return function executedFunction(...args) {
		const later = () => {
			clearTimeout(timeout);
			func(...args);
		};
		clearTimeout(timeout);
		timeout = setTimeout(later, wait);
	};
}

// --- Event Listeners ---
searchInput.addEventListener('input', debounce(loadPractices, 400));
categoryFilter.addEventListener('change', loadPractices);
featureFilter.addEventListener('change', loadPractices);
areaFilter.addEventListener('change', loadPractices);
levelFilter.addEventListener('change', loadPractices);
impactFilter.addEventListener('change', loadPractices);
resetFiltersButton.addEventListener('click', resetAllFilters);
filtersToggle?.addEventListener('click', toggleFilters);
backToTopButton?.addEventListener('click', scrollToTop);
window.addEventListener('scroll', debounce(handleScroll, 100));

// --- Keyboard Shortcuts ---
document.addEventListener('keydown', (e) => {
	// Ctrl/Cmd + K: Focus search
	if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
		e.preventDefault();
		searchInput.focus();
	}

	// Alt + T: Toggle theme
	if (e.altKey && e.key === 't') {
		e.preventDefault();
		document.querySelector('.theme-switch')?.click();
	}

	// Alt + Up Arrow: Scroll to top
	if (e.altKey && e.key === 'ArrowUp') {
		e.preventDefault();
		scrollToTop();
	}
});

// --- Initialize App ---
async function initializeApp() {
	try {
		updateResultsCount(0);

		// Fetch categories and features in parallel
		const [categories, features] = await Promise.all([fetchData(`${API_BASE}/categories`), fetchData(`${API_BASE}/features`)]);

		if (categories) {
			populateSelect(categoryFilter, categories, 'All Categories');
		}

		if (features) {
			populateSelect(featureFilter, features, 'All Features');
		}

		// Load initial practices
		await loadPractices();

		console.log(`✓ Loaded ${currentPractices.length} practices`);
	} catch (error) {
		console.error('Initialization error:', error);
		displayError('Failed to initialize app');
	}
}

// Start the app
initializeApp();
console.log('App initialized with enhanced features');
