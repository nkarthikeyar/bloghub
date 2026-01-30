// Update user info on page load
document.addEventListener("DOMContentLoaded", function () {
  const userName = localStorage.getItem("userName");
  if (userName) {
    document.getElementById("currentUser").textContent = userName;
  } else {
    window.location.href = "/singnuppage.html";
  }

  // Setup form handlers
  setupFormHandlers();
  setupStats();
  setupPreview();
});

// ============ FORM HANDLERS ============
function setupFormHandlers() {
  const titleInput = document.getElementById("blog-title");
  const excerptInput = document.getElementById("blog-excerpt");
  const contentInput = document.getElementById("blog-content");
  const tagsInput = document.getElementById("blog-tags");

  // Character counters
  if (titleInput) {
    titleInput.addEventListener("input", function () {
      updateCharCount("titleCount", this.value.length, 150);
      updatePreview("title", this.value);
    });
  }

  if (excerptInput) {
    excerptInput.addEventListener("input", function () {
      updateCharCount("excerptCount", this.value.length, 250);
      updatePreview("excerpt", this.value);
    });
  }

  if (contentInput) {
    contentInput.addEventListener("input", function () {
      updateCharCount("contentCount", this.value.length, 5000);
      updatePreview("content", this.value);
      updateStats();
    });
  }

  if (tagsInput) {
    tagsInput.addEventListener("input", function () {
      updatePreview("tags", this.value);
    });
  }

  // Form submission
  const blogForm = document.getElementById("createBlogForm");
  if (blogForm) {
    blogForm.addEventListener("submit", function (e) {
      e.preventDefault();
      publishBlog();
    });
  }
}

function updateCharCount(elementId, current, max) {
  const element = document.getElementById(elementId);
  if (element) {
    element.textContent = current + "/" + max;
    if (current > max) {
      element.style.color = "#e74c3c";
    } else {
      element.style.color = "#636e72";
    }
  }
}

// ============ STATS ============
function setupStats() {
  const contentInput = document.getElementById("blog-content");
  if (contentInput) {
    contentInput.addEventListener("input", updateStats);
  }
}

function updateStats() {
  const content = document.getElementById("blog-content").value;
  
  // Word count
  const words = content.trim().split(/\s+/).filter(w => w.length > 0).length;
  document.getElementById("wordCount").textContent = words;

  // Character count
  document.getElementById("charCount").textContent = content.length;

  // Reading time (assuming 200 words per minute)
  const readingTime = Math.ceil(words / 200) || 0;
  document.getElementById("readTime").textContent = readingTime + " min";
}

// ============ PREVIEW ============
function setupPreview() {
  const categorySelect = document.getElementById("blog-category");
  if (categorySelect) {
    categorySelect.addEventListener("change", function () {
      updatePreview("category", this.value);
    });
  }
}

function updatePreview(type, value) {
  if (type === "title") {
    document.getElementById("previewTitle").textContent = value || "Your blog title";
  } else if (type === "excerpt") {
    document.getElementById("previewExcerpt").textContent = value || "Your blog excerpt...";
  } else if (type === "category") {
    const categoryTag = document.getElementById("previewCategory");
    if (value) {
      categoryTag.textContent = value;
      categoryTag.style.display = "inline-block";
    } else {
      categoryTag.style.display = "none";
    }
  } else if (type === "tags") {
    const tags = value.split(",").map(tag => tag.trim()).filter(tag => tag);
    const previewTags = document.getElementById("previewTags");
    previewTags.innerHTML = tags.map(tag => `<span class="tag">${tag}</span>`).join("");
  }
}

// ============ DRAFT SAVING ============
function saveDraft() {
  const formData = {
    title: document.getElementById("blog-title").value,
    excerpt: document.getElementById("blog-excerpt").value,
    content: document.getElementById("blog-content").value,
    tags: document.getElementById("blog-tags").value,
    category: document.getElementById("blog-category").value,
    image: document.getElementById("blog-image").value,
    savedAt: new Date().toLocaleString()
  };

  localStorage.setItem("blogDraft", JSON.stringify(formData));
  alert("✅ Blog saved as draft!");
}

// ============ PREVIEW MODAL ============
function previewBlog() {
  const title = document.getElementById("blog-title").value;
  const content = document.getElementById("blog-content").value;
  const category = document.getElementById("blog-category").value;
  const tags = document.getElementById("blog-tags").value;

  if (!title.trim() || !content.trim()) {
    alert("Please fill in at least the title and content to preview.");
    return;
  }

  // Calculate reading time
  const words = content.trim().split(/\s+/).filter(w => w.length > 0).length;
  const readingTime = Math.ceil(words / 200);

  document.getElementById("fullPreviewTitle").textContent = title;
  document.getElementById("fullPreviewCategory").textContent = category || "Uncategorized";
  document.getElementById("fullPreviewReadTime").textContent = readingTime + " min read";
  document.getElementById("fullPreviewContent").textContent = content;

  const tagsList = tags.split(",").map(tag => tag.trim()).filter(tag => tag);
  document.getElementById("fullPreviewTags").innerHTML = tagsList.map(tag => `<span class="tag">${tag}</span>`).join(" ");

  document.getElementById("previewModal").classList.add("show");
}

function closePreview() {
  document.getElementById("previewModal").classList.remove("show");
}

// Close modal when clicking outside
window.addEventListener("click", function (e) {
  const modal = document.getElementById("previewModal");
  if (e.target === modal) {
    modal.classList.remove("show");
  }
});

// ============ PUBLISH BLOG ============
function publishBlog() {
  const title = document.getElementById("blog-title");
  const excerpt = document.getElementById("blog-excerpt");
  const content = document.getElementById("blog-content");

  // Clear previous errors
  document.querySelectorAll("#createBlogForm .error-message").forEach(el => {
    el.classList.remove("show");
    el.textContent = "";
  });

  let isValid = true;

  // Validation
  if (!title.value.trim()) {
    showError(title, "Blog title is required");
    isValid = false;
  }
  if (!excerpt.value.trim()) {
    showError(excerpt, "Short description is required");
    isValid = false;
  }
  if (!content.value.trim()) {
    showError(content, "Blog content is required");
    isValid = false;
  }

  if (!isValid) return;

  const userName = localStorage.getItem("userName");
  const userEmail = localStorage.getItem("userEmail");
  const category = document.getElementById("blog-category").value;
  const tags = document.getElementById("blog-tags").value;
  const imageUrl = document.getElementById("blog-image").value;
  const allowComments = document.getElementById("allowComments").checked;
  const markFeatured = document.getElementById("markFeatured").checked;

  const blogData = {
    title: title.value,
    excerpt: excerpt.value,
    content: content.value,
    author: { name: userName, email: userEmail },
    tags: tags.split(",").map(tag => tag.trim()).filter(tag => tag),
    category: category,
    imageUrl: imageUrl,
    allowComments: allowComments,
    markFeatured: markFeatured,
    publishedAt: new Date().toISOString()
  };

  const submitBtn = document.querySelector("#createBlogForm button[type='submit']");
  const originalText = submitBtn.innerHTML;
  submitBtn.textContent = "Publishing...";
  submitBtn.disabled = true;

  fetch("http://localhost:3000/api/blogs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(blogData)
  })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        alert("🎉 Blog published successfully!");
        document.getElementById("createBlogForm").reset();
        
        // Clear draft
        localStorage.removeItem("blogDraft");
        
        // Clear stats
        document.getElementById("wordCount").textContent = "0";
        document.getElementById("charCount").textContent = "0";
        document.getElementById("readTime").textContent = "0 min";
        
        // Reset preview
        document.getElementById("previewTitle").textContent = "Your blog title";
        document.getElementById("previewExcerpt").textContent = "Your blog excerpt...";
      } else {
        alert("Error: " + data.message);
      }
      submitBtn.innerHTML = originalText;
      submitBtn.disabled = false;
    })
    .catch(error => {
      alert("Error publishing blog: " + error.message);
      submitBtn.innerHTML = originalText;
      submitBtn.disabled = false;
    });
}

function showError(element, message) {
  const errorElement = element.parentElement.querySelector(".error-message");
  if (errorElement) {
    errorElement.textContent = message;
    errorElement.classList.add("show");
  }
}

// ============ LOGOUT ============
function logoutUser() {
  if (confirm("Are you sure you want to logout?")) {
    localStorage.removeItem("userName");
    localStorage.removeItem("userEmail");
    localStorage.removeItem("blogDraft");
    window.location.href = "/singnuppage.html";
  }
}
