// ============ API CONFIGURATION ============
const API_URL = window.location.hostname === 'localhost' 
  ? 'http://localhost:3000' 
  : 'https://bloghub-1-bzwp.onrender.com';

// ============ SUBMISSION STATE ============
let isSubmitting = false;
let isInitialized = false; // Prevent multiple initializations

// ============ PAGE INITIALIZATION ============
document.addEventListener('DOMContentLoaded', () => {
  if (isInitialized) return; // Prevent double initialization
  isInitialized = true;
  
  loadUserInfo();
  initializeEventListeners();
  setupFormValidation();
});

// ============ USER MANAGEMENT ============
function loadUserInfo() {
  const userName = localStorage.getItem('userName');
  if (!userName) {
    window.location.href = '/signuppage.html';
    return;
  }
  document.getElementById('currentUser').textContent = userName;
}

function logoutUser() {
  localStorage.removeItem('userName');
  localStorage.removeItem('userEmail');
  window.location.href = '/signuppage.html';
}

// ============ EVENT LISTENERS SETUP ============
function initializeEventListeners() {
  const form = document.getElementById('createBlogForm');
  const titleInput = document.getElementById('blog-title');
  const excerptInput = document.getElementById('blog-excerpt');
  const contentInput = document.getElementById('blog-content');
  const categoryInput = document.getElementById('blog-category');
  const tagsInput = document.getElementById('blog-tags');
  const imageInput = document.getElementById('blog-image');

  // Form submission - remove any existing listener first
  if (form) {
    // Clone and replace form to remove all event listeners
    const newForm = form.cloneNode(true);
    form.parentNode.replaceChild(newForm, form);
    
    // Add fresh event listener to the new form
    newForm.addEventListener('submit', handleFormSubmit);
    
    // Re-get references to inputs in the cloned form
    const newTitleInput = newForm.querySelector('#blog-title');
    const newExcerptInput = newForm.querySelector('#blog-excerpt');
    const newContentInput = newForm.querySelector('#blog-content');
    const newCategoryInput = newForm.querySelector('#blog-category');
    const newTagsInput = newForm.querySelector('#blog-tags');
    const newImageInput = newForm.querySelector('#blog-image');

    // Title input - live preview + char counter
    if (newTitleInput) {
      newTitleInput.addEventListener('input', (e) => {
        updateCharCounter('titleCount', e.target.value, 150);
        updatePreview('title', e.target.value);
      });
    }

    // Excerpt input - live preview + char counter
    if (newExcerptInput) {
      newExcerptInput.addEventListener('input', (e) => {
        updateCharCounter('excerptCount', e.target.value, 250);
        updatePreview('excerpt', e.target.value);
      });
    }

    // Content input - live preview + stats + char counter
    if (newContentInput) {
      newContentInput.addEventListener('input', (e) => {
        updateCharCounter('contentCount', e.target.value, 5000);
        updatePreview('content', e.target.value);
        updateStats(e.target.value);
      });
    }

    // Category select - live preview
    if (newCategoryInput) {
      newCategoryInput.addEventListener('change', (e) => {
        updatePreview('category', e.target.value);
      });
    }

    // Tags input - live preview
    if (newTagsInput) {
      newTagsInput.addEventListener('input', (e) => {
        updatePreview('tags', e.target.value);
      });
    }

    // Image input - live preview
    if (newImageInput) {
      newImageInput.addEventListener('input', (e) => {
        updatePreview('image', e.target.value);
      });
    }
  }
}

// ============ FORM SUBMIT HANDLER ============
function handleFormSubmit(e) {
  e.preventDefault();
  e.stopImmediatePropagation(); // Stop any other listeners
  
  // Prevent double submission
  if (isSubmitting) {
    alert('⏳ Blog is being published... Please wait!');
    return false;
  }
  
  if (validateForm()) {
    publishBlog();
  }
  
  return false;
}

// ============ CHARACTER COUNTER ============
function updateCharCounter(elementId, currentValue, maxLength) {
  const element = document.getElementById(elementId);
  if (element) {
    element.textContent = `${currentValue.length}/${maxLength}`;
  }
}

// ============ LIVE PREVIEW UPDATE ============
function updatePreview(field, value) {
  if (field === 'title') {
    document.getElementById('previewTitle').textContent = value || 'Your captivating title goes here';
  } else if (field === 'excerpt') {
    document.getElementById('previewExcerpt').textContent = value || 'Your story excerpt will appear here...';
  } else if (field === 'category') {
    document.getElementById('previewCategory').textContent = value || 'Category';
  } else if (field === 'tags') {
    const tagsArray = value.split(',').filter(tag => tag.trim());
    const previewTags = document.getElementById('previewTags');
    if (previewTags) {
      previewTags.innerHTML = tagsArray.map(tag => `<span>${tag.trim()}</span>`).join('');
    }
  } else if (field === 'image') {
    const previewImage = document.getElementById('previewImage');
    if (previewImage && value) {
      previewImage.innerHTML = `<img src="${value}" alt="Featured" style="width:100%; height:100%; object-fit:cover;">`;
    }
  } else if (field === 'content') {
    updateStats(value);
  }
}

// ============ STATISTICS CALCULATION ============
function updateStats(content) {
  // Word count
  const words = content.trim() ? content.trim().split(/\s+/).length : 0;
  document.getElementById('wordCount').textContent = words;
  document.getElementById('previewWordCount').textContent = words;

  // Character count
  const chars = content.length;
  document.getElementById('charCount').textContent = chars;

  // Reading time (average 200 words per minute)
  const readTime = Math.ceil(words / 200) || 0;
  document.getElementById('readTime').textContent = `${readTime} min`;
  document.getElementById('previewReadTime').textContent = readTime;
}

// ============ FORM VALIDATION ============
function setupFormValidation() {
  // This function is no longer needed since validation is handled in handleFormSubmit
  // Keeping it for backward compatibility but not adding duplicate listeners
}

function validateForm() {
  const title = document.getElementById('blog-title').value.trim();
  const excerpt = document.getElementById('blog-excerpt').value.trim();
  const content = document.getElementById('blog-content').value.trim();
  const category = document.getElementById('blog-category').value.trim();

  if (!title) {
    alert('❌ Please enter a title');
    return false;
  }
  if (!excerpt) {
    alert('❌ Please enter an excerpt');
    return false;
  }
  if (!content) {
    alert('❌ Please enter blog content');
    return false;
  }
  if (!category) {
    alert('❌ Please select a category');
    return false;
  }

  return true;
}

// ============ PUBLISH BLOG ============
async function publishBlog(e) {
  if (e) e.preventDefault();
  
  // Set submission flag
  isSubmitting = true;
  
  // Disable submit button
  const submitBtn = document.querySelector('button[type="submit"]');
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = '⏳ Publishing...';
  }

  const title = document.getElementById('blog-title').value.trim();
  const excerpt = document.getElementById('blog-excerpt').value.trim();
  const content = document.getElementById('blog-content').value.trim();
  const category = document.getElementById('blog-category').value.trim();
  const tags = document.getElementById('blog-tags').value
    .split(',')
    .map(tag => tag.trim())
    .filter(tag => tag);

  const userEmail = localStorage.getItem('userEmail') || 'unknown@example.com';
  const userName = localStorage.getItem('userName') || 'Anonymous';

  if (!title || !excerpt || !content || !category) {
    alert('❌ Please fill all required fields');
    isSubmitting = false;
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<i class="fas fa-rocket"></i> Publish Story';
    }
    return;
  }

  try {
    const response = await fetch(`${API_URL}/api/blogs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        title,
        excerpt,
        content,
        category,
        tags,
        author: {
          name: userName,
          email: userEmail
        }
      })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || 'Failed to publish blog');
    }

    alert('✅ Blog published successfully!');
    document.getElementById('createBlogForm').reset();
    
    // Reset stats
    document.getElementById('wordCount').textContent = '0';
    document.getElementById('charCount').textContent = '0';
    document.getElementById('readTime').textContent = '0 min';

    // Reset preview
    document.getElementById('previewTitle').textContent = 'Your captivating title goes here';
    document.getElementById('previewExcerpt').textContent = 'Your story excerpt will appear here...';
    document.getElementById('previewCategory').textContent = 'Category';
    document.getElementById('previewTags').innerHTML = '';

  } catch (error) {
    console.error('❌ Error publishing blog:', error);
    alert(`❌ Error: ${error.message}`);
  } finally {
    // Always reset submission flag and button
    isSubmitting = false;
    const submitBtn = document.querySelector('button[type="submit"]');
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<i class="fas fa-rocket"></i> Publish Story';
    }
  }
}

// ============ SAVE DRAFT ============
function saveDraft() {
  const title = document.getElementById('blog-title').value;
  const excerpt = document.getElementById('blog-excerpt').value;
  const content = document.getElementById('blog-content').value;
  const category = document.getElementById('blog-category').value;
  const tags = document.getElementById('blog-tags').value;

  const draft = {
    title,
    excerpt,
    content,
    category,
    tags,
    savedAt: new Date().toLocaleString()
  };

  localStorage.setItem('blogDraft', JSON.stringify(draft));
  alert('✅ Draft saved to browser!');
}

// ============ PREVIEW BLOG ============
function previewBlog() {
  const title = document.getElementById('blog-title').value || 'Untitled';
  const content = document.getElementById('blog-content').value || 'No content';
  const category = document.getElementById('blog-category').value || 'Uncategorized';
  const tags = document.getElementById('blog-tags').value;

  document.getElementById('fullPreviewTitle').textContent = title;
  document.getElementById('fullPreviewCategory').textContent = `📁 ${category}`;
  document.getElementById('fullPreviewContent').textContent = content;
  document.getElementById('fullPreviewTags').textContent = tags || 'No tags';

  const modal = document.getElementById('previewModal');
  if (modal) {
    modal.style.display = 'flex';
  }
}

// ============ CLOSE PREVIEW MODAL ============
function closePreview() {
  const modal = document.getElementById('previewModal');
  if (modal) {
    modal.style.display = 'none';
  }
}

// Close modal when clicking outside
window.addEventListener('click', (e) => {
  const modal = document.getElementById('previewModal');
  if (e.target === modal) {
    modal.style.display = 'none';
  }
});
