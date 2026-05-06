(() => {
  const form = document.getElementById("loginForm");
  const submitBtn = document.getElementById("submitBtn");
  const errorEl = document.getElementById("errorMsg");

  const showError = (msg) => {
    errorEl.textContent = msg;
    errorEl.hidden = false;
  };
  const clearError = () => {
    errorEl.textContent = "";
    errorEl.hidden = true;
  };

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearError();

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    if (!username || !password) {
      showError("Both fields are required.");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.classList.add("is-loading");

    try {
      const body = new URLSearchParams({ username, password });
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) {
        window.location.href = "/";
        return;
      }
      showError(data.error || "Sign-in failed. Please try again.");
    } catch (err) {
      showError("Network error — could not reach the server.");
    } finally {
      submitBtn.disabled = false;
      submitBtn.classList.remove("is-loading");
    }
  });
})();
