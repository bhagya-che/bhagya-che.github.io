(() => {
  "use strict";
  // Fictional records and deliberately missing ownership check for this lesson.
  const database = Object.freeze({
    101: { name: "Alice", grade: "A+", secret: "Teacher's Pet" },
    102: { name: "Bob", grade: "F", secret: "Skipped 5 classes" },
    103: { name: "Eve", grade: "C", secret: "Average Student" },
  });
  const key = "access-demo.session.v1";
  let session = null;
  try {
    const saved = localStorage.getItem(key);
    if (Object.hasOwn(database, saved)) session = saved;
  } catch {}
  const byId = (id) => document.getElementById(id);
  function show(id) {
    byId("login-screen").classList.add("hidden");
    byId("dashboard-screen").classList.remove("hidden");
    const result = byId("result_area");
    result.replaceChildren();
    if (!Object.hasOwn(database, id)) {
      result.textContent = "Student ID not found in the fictional database.";
      return;
    }
    const record = database[id],
      name = document.createElement("p"),
      grade = document.createElement("h1"),
      note = document.createElement("p");
    name.textContent = "Student Name: " + record.name;
    grade.textContent = record.grade;
    grade.className = record.grade === "F" ? "grade-fail" : "grade-pass";
    note.textContent = "Secret Note: " + record.secret;
    result.append(name, grade, note);
  }
  byId("demoLogin").addEventListener("click", () => {
    const id = byId("username_input").value.trim();
    if (!Object.hasOwn(database, id)) {
      byId("username_input").setCustomValidity(
        "Choose a fictional ID: 101, 102 or 103.",
      );
      byId("username_input").reportValidity();
      return;
    }
    session = id;
    try {
      localStorage.setItem(key, id);
    } catch {}
    const url = new URL(location.href);
    url.searchParams.set("id", id);
    try {
      history.replaceState(null, "", url);
    } catch {}
    show(id);
  });
  byId("username_input").addEventListener("input", (event) =>
    event.target.setCustomValidity(""),
  );
  byId("username_input").addEventListener("keydown", (event) => {
    if (event.key === "Enter") byId("demoLogin").click();
  });
  byId("demoLogout").addEventListener("click", () => {
    session = null;
    try {
      localStorage.removeItem(key);
    } catch {}
    const url = new URL(location.href);
    url.search = "";
    try {
      history.replaceState(null, "", url);
    } catch {}
    byId("login-screen").classList.remove("hidden");
    byId("dashboard-screen").classList.add("hidden");
  });
  const requested = new URLSearchParams(location.search).get("id");
  if (session && requested) show(requested);
})();
