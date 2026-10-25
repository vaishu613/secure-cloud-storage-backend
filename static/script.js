const API_BASE_URL = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? "http://127.0.0.1:8000"
    : "https://secure-cloud-storage-backend.onrender.com"; // Adjust if deployed

const loginForm = document.getElementById("loginForm");
const signupForm = document.getElementById("signupForm");

// ==================================================
// SIGN UP HANDLER
// ==================================================
if (signupForm) {
  signupForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const name = document.getElementById("signupName")?.value || "";
    const email = document.getElementById("signupEmail").value.trim();
    const password = document.getElementById("signupPassword").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const message = document.getElementById("signupMessage");

    if (password !== confirmPassword) {
      message.textContent = "Passwords do not match!";
      message.style.color = "red";
      return;
    }

    const passwordPattern = /^(?=.*[A-Za-z])(?=.*[0-9]).{8,}$/;
    if (!passwordPattern.test(password)) {
      message.textContent = "Password must be at least 8 characters long with letters and numbers.";
      message.style.color = "red";
      return;
    }

    message.style.color = "#3159b7";
    message.textContent = "Creating account...";

    try {
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email,
          password: password,
          full_name: name
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Registration failed.");
      }

      message.style.color = "green";
      message.textContent = "Account created successfully! Redirecting to login...";
      setTimeout(() => {
        window.location.href = "login.html";
      }, 1500);
    } catch (err) {
      message.style.color = "red";
      message.textContent = err.message;
    }
  });
}

// ==================================================
// LOGIN HANDLER
// ==================================================
if (loginForm) {
  loginForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    const email = document.getElementById("loginEmail").value.trim();
    const password = document.getElementById("loginPassword").value;
    const message = document.getElementById("loginMessage");

    message.style.color = "#3159b7";
    message.textContent = "Authenticating...";

    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email,
          password: password
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Invalid email or password.");
      }

      // Store JWT token and user info in localStorage
      localStorage.setItem("access_token", data.access_token);
      localStorage.setItem("user", JSON.stringify(data.user));

      message.style.color = "green";
      message.textContent = "Login successful! Redirecting to dashboard...";
      setTimeout(() => {
        window.location.href = "dashboard.html";
      }, 1000);
    } catch (err) {
      message.style.color = "red";
      message.textContent = err.message;
    }
  });
}
