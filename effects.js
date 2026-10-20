(() => {
  "use strict";
  const root = document.documentElement;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  const background = document.getElementById("binaryBg");
  const icon = document.querySelector(".security-icon");
  const intro = document.getElementById("cmd1")
    ? document.getElementById("intro")
    : null;
  const header = document.querySelector("header");
  let drawing = false,
    mouseX = 0,
    mouseY = 0;

  function binary() {
    if (!background) return;
    const columns = Math.ceil(innerWidth / 20),
      rows = Math.ceil(innerHeight / 20);
    background.textContent = Array.from({ length: rows }, () =>
      Array.from({ length: columns }, () =>
        Math.random() > 0.5 ? "1" : "0",
      ).join(""),
    ).join("\n");
  }
  function measureHeader() {
    if (header)
      root.style.setProperty(
        "--header-height",
        Math.ceil(header.getBoundingClientRect().height + 10) + "px",
      );
  }
  function paint() {
    drawing = false;
    if (reduced.matches) return;
    const y = window.scrollY;
    if (intro) {
      const fraction = Math.min(1, y / Math.max(1, intro.offsetHeight));
      intro.style.transform = `translateY(${Math.min(y, intro.offsetHeight) * 0.5}px)`;
      intro.style.opacity = String(1 - fraction);
      const indicator = intro.querySelector(".scroll-indicator");
      if (indicator) indicator.style.opacity = String(Math.max(0, 1 - y / 300));
    }
    if (background)
      background.style.transform = `translateY(${-Math.min(y, innerHeight) * 0.3}px)`;
    if (icon && intro)
      icon.style.transform = `translate(${mouseX + y * 0.02}px, ${mouseY - y * 0.01}px)`;
  }
  function schedule() {
    if (!drawing) {
      drawing = true;
      requestAnimationFrame(paint);
    }
  }
  binary();
  measureHeader();
  if ("ResizeObserver" in window && header)
    new ResizeObserver(measureHeader).observe(header);
  let resizeTimer;
  window.addEventListener(
    "resize",
    () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        binary();
        measureHeader();
        schedule();
      }, 100);
    },
    { passive: true },
  );
  window.addEventListener("scroll", schedule, { passive: true });
  if (intro && matchMedia("(pointer: fine)").matches)
    document.addEventListener(
      "pointermove",
      (event) => {
        mouseX = (event.clientX / innerWidth - 0.5) * 20;
        mouseY = (event.clientY / innerHeight - 0.5) * 20;
        schedule();
      },
      { passive: true },
    );
  if (!reduced.matches && "IntersectionObserver" in window) {
    root.classList.add("js-motion");
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries)
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            observer.unobserve(entry.target);
          }
      },
      { threshold: 0.05 },
    );
    document
      .querySelectorAll(".reveal")
      .forEach((element) => observer.observe(element));
  }
  reduced.addEventListener("change", () => {
    if (reduced.matches) {
      root.classList.remove("js-motion");
      for (const el of [intro, background, icon])
        if (el) {
          el.style.transform = "";
          el.style.opacity = "";
        }
    }
  });

  // Keep the original typing effect; the CSS cursor supplies its blink.
  async function type(element, value) {
    element.textContent = "";
    for (const letter of value) {
      if (reduced.matches || document.hidden) {
        element.textContent = value;
        return;
      }
      element.textContent += letter;
      await new Promise((resolve) => setTimeout(resolve, 45));
    }
  }
  async function terminal() {
    if (!intro || reduced.matches) return;
    intro.classList.add("terminal-typing");
    for (const n of [1, 2]) {
      const command = document.getElementById("cmd" + n),
        cursor = document.getElementById("cursor" + n);
      cursor.hidden = false;
      await type(command, command.textContent);
      cursor.hidden = true;
      document.getElementById("output" + n).style.opacity = "1";
    }
    intro.classList.remove("terminal-typing");
  }
  terminal();

  const toggle = document.getElementById("activityToggle"),
    sidebar = document.getElementById("notificationSidebar");
  if (toggle && sidebar) {
    const compact = matchMedia("(max-width: 1200px)");
    function sync() {
      const open = !compact.matches || sidebar.classList.contains("active");
      sidebar.inert = !open;
      toggle.setAttribute("aria-expanded", String(open));
    }
    toggle.addEventListener("click", () => {
      sidebar.classList.toggle("active");
      sync();
    });
    document.addEventListener("keydown", (event) => {
      if (
        event.key === "Escape" &&
        compact.matches &&
        sidebar.classList.contains("active")
      ) {
        sidebar.classList.remove("active");
        sync();
        toggle.focus();
      }
    });
    compact.addEventListener("change", sync);
    sync();
  }
})();
