(() => {
  "use strict";
  const key = "ctf.progress.v1",
    modal = document.getElementById("victoryModal"),
    close = document.getElementById("closeVictory"),
    form = document.getElementById("loginForm");
  let solved = false,
    previousFocus;
  try {
    solved = localStorage.getItem(key) === "auth";
    if (!solved) {
      const legacy = JSON.parse(localStorage.getItem("solvedCTFs") || "[]");
      solved = Array.isArray(legacy) && legacy.includes("auth");
    }
  } catch {}
  function render() {
    document.getElementById("authStatus").textContent = solved
      ? "✓ Solved"
      : "Ready";
    document.getElementById("auth").classList.toggle("solved", solved);
    document.getElementById("ctfProgress").textContent =
      `Progress: ${solved ? 1 : 0} / 1 available challenge completed`;
  }
  function hide() {
    modal.hidden = true;
    document.body.style.overflow = "";
    previousFocus?.focus();
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    form.querySelector(".error-message")?.remove();
    const username = document.getElementById("username").value,
      password = document.getElementById("password").value;
    const debug = new URLSearchParams(location.search).get("debug") === "true";
    // Deliberately insecure fictional authentication for this source-inspection lesson only.
    if ((username === "admin" && password === "secretpass123") || debug) {
      solved = true;
      try {
        localStorage.setItem(key, "auth");
      } catch {}
      render();
      previousFocus = document.activeElement;
      modal.hidden = false;
      document.body.style.overflow = "hidden";
      close.focus();
    } else {
      const error = document.createElement("p");
      error.className = "error-message";
      error.setAttribute("role", "alert");
      error.textContent =
        "Demo login failed. Hint: inspect ctf.js or try ?debug=true in the URL.";
      form.append(error);
    }
  });
  close.addEventListener("click", hide);
  modal.addEventListener("click", (e) => {
    if (e.target === modal) hide();
  });
  document.addEventListener("keydown", (e) => {
    if (modal.hidden) return;
    if (e.key === "Escape") hide();
    if (e.key === "Tab") {
      e.preventDefault();
      close.focus();
    }
  });
  render();
})();
