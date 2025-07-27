// public/app.js

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

// --- Functions ---

function displayError(message) {
	console.error('Error:', message);
	errorMessage.textContent = `Error: ${message}. Please try refreshing.`;
	errorMessage.style.display = 'block';
	if (tableBody) {
		tableBody.textContent = ''; // Clear existing content
		const tr = document.createElement('tr');
		const td = document.createElement('td');
		td.setAttribute('colspan', '12'); // Updated colspan to match total columns
		td.textContent = 'Failed to load data.';
		tr.appendChild(td);
		tableBody.appendChild(tr);
	}
}

function clearError() {
	errorMessage.textContent = '';
	errorMessage.style.display = 'none';
}

async function fetchData(url) {
	try {
		const response = await fetch(url);
		if (!response.ok) {
			let errorMsg = `HTTP error! Status: ${response.status}`;
			try {
				const errData = await response.json();
				errorMsg += ` - ${errData.error || 'Unknown server error'}`;
			} catch (e) {}
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

function renderTable(practices) {
	if (!tableBody) return;
	clearError();

	// Clear existing content
	tableBody.textContent = '';

	if (!practices || practices.length === 0) {
		const tr = document.createElement('tr');
		const td = document.createElement('td');
		td.setAttribute('colspan', '12'); // Updated colspan to match total columns
		td.textContent = 'No practices found matching your criteria.';
		tr.appendChild(td);
		tableBody.appendChild(tr);
		return;
	}

	practices.forEach((p) => {
		const tr = document.createElement('tr');
		
		const createCell = (label, content, isCode = false) => {
			const td = document.createElement('td');
			td.setAttribute('data-label', label);
			if (isCode) {
				const code = document.createElement('code');
				code.textContent = content || 'N/A';
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
				a.rel = 'external noopener noreferrer';
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
		tr.appendChild(createLinkCell(
			'Source',
			p.source_reference?.startsWith('https://') ? 'Documentation' : p.source_reference,
			p.source_reference?.startsWith('https://') ? p.source_reference : null
		));
		tr.appendChild(createCell('Notes', p.notes || ''));

		tableBody.appendChild(tr);
	});
}

/** Populates a select dropdown */
function populateSelect(selectElement, items, defaultOptionText) {
	if (!selectElement) return;
	// Keep the default "All..." option
	selectElement.innerHTML = `<option value="">${defaultOptionText}</option>`;
	items.forEach((item) => {
		const option = document.createElement('option');
		option.value = item.id; // Use ID as the value
		option.textContent = item.name; // Display name
		selectElement.appendChild(option);
	});
}

async function loadPractices() {
	if (!tableBody) return;
	tableBody.textContent = ''; // Clear existing content
	const tr = document.createElement('tr');
	const td = document.createElement('td');
	td.setAttribute('colspan', '12'); // Updated colspan to match total columns
	td.textContent = 'Loading...';
	tr.appendChild(td);
	tableBody.appendChild(tr);

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
	if (practices !== null) {
		renderTable(practices);
	}
}

function resetAllFilters() {
	searchInput.value = '';
	categoryFilter.value = '';
	featureFilter.value = '';
	areaFilter.value = '';
	levelFilter.value = '';
	impactFilter.value = '';
	loadPractices(); // Reload data with no filters
}

// --- Event Listeners ---
searchInput.addEventListener('input', debounce(loadPractices, 350)); // Debounce search
categoryFilter.addEventListener('change', loadPractices);
featureFilter.addEventListener('change', loadPractices);
areaFilter.addEventListener('change', loadPractices);
levelFilter.addEventListener('change', loadPractices);
impactFilter.addEventListener('change', loadPractices);
resetFiltersButton.addEventListener('click', resetAllFilters);

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

// --- Initial Load ---
async function initializeApp() {
	// Fetch categories and features in parallel for faster loading
	const [categories, features] = await Promise.all([fetchData(`${API_BASE}/categories`), fetchData(`${API_BASE}/features`)]);

	if (categories) populateSelect(categoryFilter, categories, 'All Categories');
	if (features) populateSelect(featureFilter, features, 'All Features');

	// Load initial practices (all)
	await loadPractices();
}

initializeApp();
console.log('App initialized (ESM) for new schema');
