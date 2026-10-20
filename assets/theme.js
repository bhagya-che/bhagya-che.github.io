(() => {
  "use strict";
  const key = "portfolio.theme.v1";
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  let preference = "system";
  try {
    const saved = localStorage.getItem(key);
    if (saved === "light" || saved === "dark") preference = saved;
  } catch {}
  function apply() {
    const theme =
      preference === "system" ? (media.matches ? "dark" : "light") : preference;
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      const label = `Switch to ${theme === "dark" ? "light" : "dark"} mode`;
      button.setAttribute("aria-label", label);
      button.title = label;
    });
    document.querySelectorAll("[data-theme-auto]").forEach((button) => {
      button.setAttribute("aria-pressed", String(preference === "system"));
      button.title =
        preference === "system"
          ? "Following browser theme"
          : "Use browser theme";
    });
    window.dispatchEvent(new CustomEvent("themechange", { detail: theme }));
  }
  function save(value) {
    preference = value;
    try {
      if (value === "system") localStorage.removeItem(key);
      else localStorage.setItem(key, value);
    } catch {}
    apply();
  }
  apply();
  document.addEventListener("DOMContentLoaded", () => {
    apply();
    document
      .querySelectorAll("[data-theme-toggle]")
      .forEach((button) =>
        button.addEventListener("click", () =>
          save(
            document.documentElement.dataset.theme === "dark"
              ? "light"
              : "dark",
          ),
        ),
      );
    document
      .querySelectorAll("[data-theme-auto]")
      .forEach((button) =>
        button.addEventListener("click", () => save("system")),
      );
  });
  media.addEventListener("change", () => {
    if (preference === "system") apply();
  });
  window.addEventListener("storage", (event) => {
    if (event.key === key) {
      preference = ["light", "dark"].includes(event.newValue)
        ? event.newValue
        : "system";
      apply();
    }
  });
})();
