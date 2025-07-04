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
	if (tableBody) tableBody.innerHTML = '<tr><td colspan="9">Failed to load data.</td></tr>'; // Update colspan
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

	if (!practices || practices.length === 0) {
		tableBody.innerHTML = '<tr><td colspan="9">No practices found matching your criteria.</td></tr>'; // Update colspan
		return;
	}

	tableBody.innerHTML = practices
		.map((p) => {
			const isSourceUrl = p.source_reference &&
				p.source_reference.startsWith('https://');

			return `
                <tr>
                    <td data-label="Title">${escapeHTML(p.title)}</td>
                    <td data-label="Category">${escapeHTML(p.category_name || 'N/A')}</td>
                    <td data-label="Domain">${escapeHTML(p.domain)}</td>
                    <td data-label="Level">${escapeHTML(p.recommendation_level)}</td>
                    <td data-label="Impact">${escapeHTML(p.impact_level || 'N/A')}</td>
                    <td data-label="Difficulty">${escapeHTML(p.difficulty_level || 'N/A')}</td>
                    <td data-label="Description">${escapeHTML(p.description)}</td>
                    <td data-label="Prerequisites">${escapeHTML(p.prerequisites || 'N/A')}</td>
                    <td data-label="Feature">${p.feature_url
											? `<a href="${escapeHTML(p.feature_url)}" target="_blank" rel="external noopener noreferrer">${escapeHTML(
														p.feature_name || 'Link'
												  )}</a>`
											: escapeHTML(p.feature_name || 'N/A')}</td>
                    <td data-label="Configuration"><code>${escapeHTML(p.expressions_configuration_details || 'N/A')}</code></td>
                    <td data-label="Source">${isSourceUrl
											? `<a href="${escapeHTML(p.source_reference)}" target="_blank" rel="external noopener noreferrer">Documentation</a>`
											: escapeHTML(p.source_reference || 'N/A')}</td>
                    <td data-label="Notes">${escapeHTML(p.notes || '')}</td>
                </tr>`;
		})
		.join('');
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
	tableBody.innerHTML = '<tr><td colspan="9">Loading...</td></tr>'; // Update colspan

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

function escapeHTML(str) {
	if (str === null || str === undefined) return '';
	return str.toString().replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
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
