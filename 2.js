// Show Login Form (default view)
function showLoginForm() {
  document.getElementById("signupForm").style.display = "none";
  document.getElementById("loginForm").style.display = "block";
  
  const formHeader = document.querySelector(".form-header");
  if (formHeader) {
    formHeader.innerHTML = "<h2 id=\"form-title\">Welcome Back</h2><p id=\"form-subtitle\">Sign in to continue to your blog</p>";
  }
}

// Show Signup Form
function showSignupForm() {
  document.getElementById("loginForm").style.display = "none";
  document.getElementById("signupForm").style.display = "block";
  
  const formHeader = document.querySelector(".form-header");
  if (formHeader) {
    formHeader.innerHTML = "<h2 id=\"form-title\">Create Your Account</h2><p id=\"form-subtitle\">Start sharing your amazing stories</p>";
  }
}

// Show Blog Form after login - Redirect to professional blog editor
function showBlogForm(userName) {
  setTimeout(() => {
    window.location.href = "/blog.html";
  }, 500);
}

// Logout - Go back to signup
function logoutUser() {
  localStorage.removeItem("userName");
  localStorage.removeItem("userEmail");
  
  document.getElementById("signupForm").reset();
  document.getElementById("loginForm").reset();
  document.getElementById("createBlogForm").reset();
  
  document.getElementById("signupForm").style.display = "block";
  document.getElementById("loginForm").style.display = "none";
  document.getElementById("createBlogForm").style.display = "none";
  
  const formHeader = document.querySelector(".form-header");
  if (formHeader) {
    formHeader.innerHTML = "<h2 id=\"form-title\">Create Your Account</h2><p id=\"form-subtitle\">Start sharing your amazing stories</p>";
  }
  
  alert("Logged out successfully! See you soon ??");
}

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function getPasswordStrength(password) {
  let strength = 0;
  if (password.length >= 8) strength++;
  if (/[A-Z]/.test(password)) strength++;
  if (/[0-9]/.test(password)) strength++;
  if (/[^A-Za-z0-9]/.test(password)) strength++;
  return strength;
}

function updatePasswordStrength(password) {
  const strengthBar = document.querySelector(".strength-bar");
  if (!strengthBar) return;
  const strength = getPasswordStrength(password);
  strengthBar.classList.remove("weak", "medium", "strong");
  if (password.length === 0) {
    strengthBar.style.width = "0%";
  } else if (strength <= 1) {
    strengthBar.classList.add("weak");
    strengthBar.style.width = "33%";
  } else if (strength <= 2) {
    strengthBar.classList.add("medium");
    strengthBar.style.width = "66%";
  } else {
    strengthBar.classList.add("strong");
    strengthBar.style.width = "100%";
  }
}

document.addEventListener("DOMContentLoaded", function () {
  // Password visibility toggle
  const togglePasswordButtons = document.querySelectorAll(".toggle-password");
  togglePasswordButtons.forEach((btn) => {
    btn.addEventListener("click", function () {
      const input = this.previousElementSibling;
      if (input.type === "password") {
        input.type = "text";
        this.classList.remove("fa-eye");
        this.classList.add("fa-eye-slash");
      } else {
        input.type = "password";
        this.classList.remove("fa-eye-slash");
        this.classList.add("fa-eye");
      }
    });
  });

  // Password strength meter
  const passwordInput = document.getElementById("password");
  if (passwordInput) {
    passwordInput.addEventListener("input", function () {
      updatePasswordStrength(this.value);
    });
  }
});

// SIGNUP FORM HANDLER
document.getElementById("signupForm").addEventListener("submit", function (e) {
  e.preventDefault();
  const name = document.getElementById("name");
  const email = document.getElementById("email");
  const password = document.getElementById("password");
  const confirmPassword = document.getElementById("confirm-password");
  const agreeTerms = document.getElementById("agree-terms");

  document.querySelectorAll("#signupForm .error-message").forEach((el) => (el.textContent = ""));
  let isValid = true;

  if (!name.value.trim()) {
    name.parentElement.querySelector(".error-message").textContent = "Full name is required";
    isValid = false;
  }
  if (!email.value.trim()) {
    email.parentElement.querySelector(".error-message").textContent = "Email is required";
    isValid = false;
  } else if (!isValidEmail(email.value)) {
    email.parentElement.querySelector(".error-message").textContent = "Invalid email format";
    isValid = false;
  }
  if (!password.value) {
    password.parentElement.querySelector(".error-message").textContent = "Password is required";
    isValid = false;
  } else if (password.value.length < 6) {
    password.parentElement.querySelector(".error-message").textContent = "Password must be at least 6 characters";
    isValid = false;
  }
  if (!confirmPassword.value) {
    confirmPassword.parentElement.querySelector(".error-message").textContent = "Please confirm your password";
    isValid = false;
  } else if (password.value !== confirmPassword.value) {
    confirmPassword.parentElement.querySelector(".error-message").textContent = "Passwords do not match";
    isValid = false;
  }
  if (!agreeTerms.checked) {
    alert("Please agree to the Terms & Conditions");
    isValid = false;
  }

  if (isValid) {
    const userData = {
      name: name.value,
      email: email.value,
      password: password.value,
    };
    const submitBtn = document.querySelector("#signupForm .auth-btn");
    submitBtn.textContent = "Creating Account...";
    submitBtn.disabled = true;

    fetch("http://localhost:3000/api/signup", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(userData),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          localStorage.setItem("userName", data.user.name);
          localStorage.setItem("userEmail", data.user.email);
          alert("Account created! ? Now please log in with your credentials.");
          document.getElementById("signupForm").reset();
          showLoginForm();
          submitBtn.textContent = "Create Account";
          submitBtn.disabled = false;
        } else {
          alert("Error: " + data.message);
          submitBtn.textContent = "Create Account";
          submitBtn.disabled = false;
        }
      })
      .catch((error) => {
        alert("Error connecting to server!");
        submitBtn.textContent = "Create Account";
        submitBtn.disabled = false;
      });
  }
});

// LOGIN FORM HANDLER
document.getElementById("loginForm").addEventListener("submit", function (e) {
  e.preventDefault();
  const email = document.getElementById("login-email");
  const password = document.getElementById("login-password");
  document.querySelectorAll("#loginForm .error-message").forEach((el) => (el.textContent = ""));
  let isValid = true;

  if (!email.value.trim()) {
    email.parentElement.querySelector(".error-message").textContent = "Email is required";
    isValid = false;
  } else if (!isValidEmail(email.value)) {
    email.parentElement.querySelector(".error-message").textContent = "Invalid email format";
    isValid = false;
  }
  if (!password.value) {
    password.parentElement.querySelector(".error-message").textContent = "Password is required";
    isValid = false;
  }

  if (isValid) {
    const loginData = {email: email.value, password: password.value};
    const submitBtn = document.querySelector("#loginForm .auth-btn");
    submitBtn.textContent = "Signing In...";
    submitBtn.disabled = true;

    fetch("http://localhost:3000/api/login", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(loginData),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          localStorage.setItem("userName", data.user.name);
          localStorage.setItem("userEmail", data.user.email);
          alert("Login successful! ? Ready to create your blog?");
          document.getElementById("loginForm").reset();
          showBlogForm(data.user.name);
          submitBtn.textContent = "Sign In";
          submitBtn.disabled = false;
        } else {
          alert("Error: " + data.message);
          submitBtn.textContent = "Sign In";
          submitBtn.disabled = false;
        }
      })
      .catch((error) => {
        alert("Error connecting to server!");
        submitBtn.textContent = "Sign In";
        submitBtn.disabled = false;
      });
  }
});

// BLOG FORM HANDLER
document.addEventListener("DOMContentLoaded", function () {
  const createBlogForm = document.getElementById("createBlogForm");
  if (createBlogForm) {
    createBlogForm.addEventListener("submit", function (e) {
      e.preventDefault();
      const title = document.getElementById("blog-title");
      const excerpt = document.getElementById("blog-excerpt");
      const content = document.getElementById("blog-content");
      const tags = document.getElementById("blog-tags");

      document.querySelectorAll("#createBlogForm .error-message").forEach((el) => (el.textContent = ""));
      let isValid = true;

      if (!title.value.trim()) {
        title.parentElement.querySelector(".error-message").textContent = "Blog title is required";
        isValid = false;
      }
      if (!excerpt.value.trim()) {
        excerpt.parentElement.querySelector(".error-message").textContent = "Short description is required";
        isValid = false;
      }
      if (!content.value.trim()) {
        content.parentElement.querySelector(".error-message").textContent = "Blog content is required";
        isValid = false;
      }

      if (isValid) {
        const userName = localStorage.getItem("userName");
        const userEmail = localStorage.getItem("userEmail");
        const blogData = {
          title: title.value,
          excerpt: excerpt.value,
          content: content.value,
          author: {name: userName, email: userEmail},
          tags: tags.value.split(",").map(tag => tag.trim()).filter(tag => tag)
        };

        const submitBtn = document.querySelector("#createBlogForm .auth-btn");
        submitBtn.textContent = "Publishing...";
        submitBtn.disabled = true;

        fetch("http://localhost:3000/api/blogs", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(blogData),
        })
          .then((response) => response.json())
          .then((data) => {
            if (data.success) {
              alert("Blog published successfully! ??");
              document.getElementById("createBlogForm").reset();
              title.value = "";
              excerpt.value = "";
              content.value = "";
              tags.value = "";
            } else {
              alert("Error: " + data.message);
            }
            submitBtn.textContent = "Publish Blog";
            submitBtn.disabled = false;
          })
          .catch((error) => {
            alert("Error publishing blog");
            submitBtn.textContent = "Publish Blog";
            submitBtn.disabled = false;
          });
      }
    });
  }
});
