// Dashboard.js
const API_BASE = '/api';

// DOM Elements
const form = document.getElementById('practiceForm');
const categorySelect = document.getElementById('category');
const featureSelect = document.getElementById('feature');
const successMessage = document.getElementById('successMessage');
const errorMessage = document.getElementById('errorMessage');

// Load categories and features on page load
async function initializeDashboard() {
    try {
        const [categories, features] = await Promise.all([
            fetch(`${API_BASE}/categories`).then(r => r.json()),
            fetch(`${API_BASE}/features`).then(r => r.json())
        ]);

        if (categories.success && categories.data) {
            populateSelect(categorySelect, categories.data);
        }
        if (features.success && features.data) {
            populateSelect(featureSelect, features.data);
        }
    } catch (error) {
        showError('Failed to load initial data');
        console.error('Initialization error:', error);
    }
}

function populateSelect(selectElement, items) {
    // Keep the first "Select..." option
    const firstOption = selectElement.firstElementChild;
    selectElement.innerHTML = '';
    selectElement.appendChild(firstOption);
    
    items.forEach(item => {
        const option = document.createElement('option');
        option.value = item.id;
        option.textContent = item.name;
        selectElement.appendChild(option);
    });
}

function showSuccess(message = 'Practice saved successfully!') {
    successMessage.textContent = message;
    successMessage.style.display = 'block';
    errorMessage.style.display = 'none';
    
    // Automatically hide after 5 seconds with fade out
    setTimeout(() => {
        successMessage.style.opacity = '0';
        setTimeout(() => {
            successMessage.style.display = 'none';
            successMessage.style.opacity = '1';
        }, 300);
    }, 5000);
}

function showError(message) {
    errorMessage.textContent = message;
    errorMessage.style.display = 'block';
    successMessage.style.display = 'none';
}

async function handleSubmit(event) {
    event.preventDefault();
    const submitButton = form.querySelector('button[type="submit"]');
    submitButton.classList.add('loading');
    
    const formData = new FormData(form);
    const practice = {
        title: formData.get('title'),
        description: formData.get('description'),
        domain: formData.get('domain'),
        category_id: formData.get('category') || null,
        feature_id: formData.get('feature') || null,
        recommendation_level: formData.get('recommendationLevel'),
        impact_level: formData.get('impactLevel'),
        difficulty_level: formData.get('difficultyLevel') || null,
        prerequisites: formData.get('prerequisites') || null,
        expressions_configuration_details: formData.get('configuration') || null,
        source_reference: formData.get('sourceReference') || null,
        notes: formData.get('notes') || null
    };

    try {
        const response = await fetch(`${API_BASE}/practices`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(practice)
        });

        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'Failed to save practice');
        }

        if (result.success) {
            showSuccess();
            form.reset();
        } else {
            throw new Error(result.error || 'Failed to save practice');
        }
    } catch (error) {
        showError(error.message);
        console.error('Submission error:', error);
    } finally {
        submitButton.classList.remove('loading');
    }
}

// Event Listeners
form.addEventListener('submit', handleSubmit);
form.addEventListener('reset', () => {
    errorMessage.style.display = 'none';
    successMessage.style.display = 'none';
});

// Initialize the dashboard
initializeDashboard();