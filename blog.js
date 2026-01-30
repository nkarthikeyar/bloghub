// ============ API CONFIGURATION ============
const API_URL = window.location.hostname === 'localhost' 
  ? 'http://localhost:3000' 
  : 'https://bloghub-1-bzwp.onrender.com';

// ============ SUBMISSION STATE ============
let isSubmitting = false;
let listenersAttached = false;

function generateRequestId() {
  if (window.crypto && typeof window.crypto.randomUUID === 'function') {
    return window.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

// ============ PAGE INITIALIZATION ============
window.addEventListener('DOMContentLoaded', () => {
  console.log('🚀 Blog page loaded');
  loadUserInfo();
  attachAllListeners();
});

function showToast(message) {
  let toast = document.getElementById('toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    toast.style.position = 'fixed';
    toast.style.right = '16px';
    toast.style.bottom = '16px';
    toast.style.zIndex = '9999';
    toast.style.padding = '12px 14px';
    toast.style.borderRadius = '12px';
    toast.style.background = 'rgba(15, 23, 42, 0.92)';
    toast.style.color = '#fff';
    toast.style.boxShadow = '0 10px 30px rgba(0,0,0,0.25)';
    toast.style.fontSize = '14px';
    toast.style.maxWidth = '320px';
    toast.style.backdropFilter = 'blur(8px)';
    document.body.appendChild(toast);
  }

  toast.textContent = message;
  toast.style.opacity = '1';

  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => {
    toast.style.opacity = '0';
  }, 2500);
}

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

// ============ ATTACH ALL EVENT LISTENERS ============
function attachAllListeners() {
  // Prevent attaching listeners multiple times
  if (listenersAttached) {
    console.log('⚠️ Listeners already attached, skipping');
    return;
  }
  listenersAttached = true;
  
  const form = document.getElementById('createBlogForm');
  if (!form) {
    console.error('❌ Form not found!');
    return;
  }

  // CRITICAL: Use 'submit' event directly on form - NO double listeners
  form.addEventListener('submit', handleFormSubmit, { once: false });
  console.log('✅ Form submit listener attached');

  // Attach input listeners for live preview
  attachInputListeners();
}

// ============ ATTACH INPUT LISTENERS ============
function attachInputListeners() {
  const titleInput = document.getElementById('blog-title');
  const excerptInput = document.getElementById('blog-excerpt');
  const contentInput = document.getElementById('blog-content');
  const categoryInput = document.getElementById('blog-category');
  const tagsInput = document.getElementById('blog-tags');
  const imageInput = document.getElementById('blog-image');

  if (titleInput) {
    titleInput.addEventListener('input', (e) => {
      updateCharCounter('titleCount', e.target.value, 150);
      updatePreview('title', e.target.value);
    });
  }

  if (excerptInput) {
    excerptInput.addEventListener('input', (e) => {
      updateCharCounter('excerptCount', e.target.value, 250);
      updatePreview('excerpt', e.target.value);
    });
  }

  if (contentInput) {
    contentInput.addEventListener('input', (e) => {
      updateCharCounter('contentCount', e.target.value, 5000);
      updatePreview('content', e.target.value);
      updateStats(e.target.value);
    });
  }

  if (categoryInput) {
    categoryInput.addEventListener('change', (e) => {
      updatePreview('category', e.target.value);
    });
  }

  if (tagsInput) {
    tagsInput.addEventListener('input', (e) => {
      updatePreview('tags', e.target.value);
    });
  }

  if (imageInput) {
    imageInput.addEventListener('input', (e) => {
      updatePreview('image', e.target.value);
    });
  }
}

// ============ FORM SUBMIT HANDLER ============
async function handleFormSubmit(e) {
  e.preventDefault();
  e.stopImmediatePropagation();
  
  console.log('📝 Form submit triggered');
  
  // CRITICAL: Check submission lock
  if (isSubmitting) {
    console.warn('⚠️ Already submitting, blocking double submission');
    alert('⏳ Blog is being published... Please wait!');
    return false;
  }

  // Validate form
  if (!validateForm()) {
    console.warn('❌ Form validation failed');
    return false;
  }

  // Set submission flag IMMEDIATELY
  isSubmitting = true;
  console.log('🔒 Submission lock enabled');

  // Disable button
  const submitBtn = document.querySelector('button[type="submit"]');
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = '⏳ Publishing...';
    submitBtn.style.opacity = '0.6';
  }

  try {
    // Get form data
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

    if (!userName || userName === 'Anonymous' || !userEmail || userEmail === 'unknown@example.com') {
      isSubmitting = false;
      showToast('❌ Login expired. Please login again.');
      setTimeout(() => {
        window.location.href = '/signuppage.html';
      }, 800);
      return false;
    }

    const requestId = generateRequestId();
    console.log('🧾 RequestId:', requestId);

    console.log('📤 Sending blog to server:', { title, category, tags });

    // SINGLE fetch request only
    const response = await fetch(`${API_URL}/api/blogs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Request-Id': requestId
      },
      body: JSON.stringify({
        requestId,
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

    console.log('✅ Server response:', data);
    showToast(data.message || '✅ Blog published successfully!');

    // Reset form
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
    // Always unlock submission
    isSubmitting = false;
    console.log('🔓 Submission lock disabled');

    const submitBtn = document.querySelector('button[type="submit"]');
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<i class="fas fa-rocket"></i> Publish Story';
      submitBtn.style.opacity = '1';
    }
  }

  return false;
}

// ============ FORM VALIDATION ============
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
