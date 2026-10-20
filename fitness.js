(() => {
  "use strict";
  const { sessions, meals, quickFoods } = window.FITNESS_DATA;
  const $ = (id) => document.getElementById(id);
  const STORAGE = "fitness.planner.v1",
    REMEMBER = "fitness.remember.v1";
  const DAYS = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
  ];
  const DAY = 86400000,
    MAX_FILE = 2 * 1024 * 1024;
  const numeric = {
    weight: [20, 400],
    waist: [20, 300],
    sleep: [0, 24],
    steps: [0, 200000],
    posing: [0, 240],
  };
  const choices = {
    energy: ["", "high", "okay", "low"],
    cycle: [
      "",
      "period",
      "follicular",
      "ovulatory",
      "luteal",
      "irregular",
      "contraception",
    ],
  };
  const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  const dateValue = (d) => Date.parse(d + "T12:00:00Z");
  const iso = (time) => new Date(time).toISOString().slice(0, 10);
  const addDays = (d, n) => iso(dateValue(d) + n * DAY);
  const localToday = () => {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  };
  const dayIndex = (date) => (new Date(dateValue(date)).getUTCDay() + 6) % 7;
  const fmt = (d) =>
    new Date(dateValue(d)).toLocaleDateString(undefined, {
      timeZone: "UTC",
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  const calories = (food) => Math.round(4 * food.p + 4 * food.c + 9 * food.f);
  const totals = (foods) =>
    foods.reduce((a, x) => ({ p: a.p + x.p, c: a.c + x.c, f: a.f + x.f }), {
      p: 0,
      c: 0,
      f: 0,
    });
  const fresh = () => ({
    settings: {
      start: localToday(),
      end: addDays(localToday(), 41),
      goal: null,
      calories: null,
    },
    logs: {},
  });
  let state = fresh(),
    selected = localToday(),
    mealDay = dayIndex(selected),
    remember = true,
    toastTimer;
  function element(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === "class") node.className = value;
      else if (key === "click") node.addEventListener("click", value);
      else if (key === "change") node.addEventListener("change", value);
      else if (key === "checked") node.checked = value;
      else node.setAttribute(key, String(value));
    }
    children
      .flat()
      .forEach((child) =>
        node.append(
          child instanceof Node
            ? child
            : document.createTextNode(String(child)),
        ),
      );
    return node;
  }
  function toast(text) {
    clearTimeout(toastTimer);
    $("toast").textContent = text;
    $("toast").classList.add("visible");
    toastTimer = setTimeout(() => $("toast").classList.remove("visible"), 4500);
  }
  function object(value) {
    return (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.getPrototypeOf(value) === Object.prototype
    );
  }
  function fail(message) {
    throw new Error(message);
  }
  function checkKeys(o, allowed) {
    if (!object(o)) fail("Expected an object.");
    for (const key of Object.keys(o))
      if (!allowed.includes(key)) fail("Unexpected field in backup.");
  }
  function validDate(value) {
    return (
      typeof value === "string" &&
      /^\d{4}-\d{2}-\d{2}$/.test(value) &&
      value >= "1900-01-01" &&
      value <= "2200-12-31" &&
      Number.isFinite(dateValue(value)) &&
      iso(dateValue(value)) === value
    );
  }
  function number(value, min, max) {
    if (typeof value !== "number" && typeof value !== "string")
      fail("Invalid numeric value.");
    if (value === "") fail("Missing number.");
    const n = Number(value);
    if (!Number.isFinite(n) || n < min || n > max)
      fail("A number is outside its allowed range.");
    return n;
  }
  function text(value, max) {
    if (typeof value !== "string" || value.length > max)
      fail("Invalid or overlong text.");
    return value;
  }
  function option(value, list) {
    if (!list.includes(value)) fail("Unexpected option.");
    return value;
  }
  function settings(value) {
    checkKeys(value, ["start", "end", "goal", "calories"]);
    if (
      !validDate(value.start) ||
      !validDate(value.end) ||
      value.end < value.start ||
      dateValue(value.end) - dateValue(value.start) > 729 * DAY
    )
      fail("Choose valid plan dates within a two-year window.");
    return {
      start: value.start,
      end: value.end,
      goal:
        value.goal == null || value.goal === ""
          ? null
          : number(value.goal, 20, 400),
      calories:
        value.calories == null || value.calories === ""
          ? null
          : number(value.calories, 1, 15000),
    };
  }
  function validateLog(value) {
    checkKeys(value, [
      "foods",
      "checks",
      "lifts",
      "mode",
      "effort",
      "finished",
      ...Object.keys(numeric),
      ...Object.keys(choices),
      "notes",
    ]);
    const out = {
      foods: [],
      checks: {},
      lifts: {},
      mode: "gym",
      effort: "normal",
      finished: false,
    };
    if (value.foods !== undefined) {
      if (!Array.isArray(value.foods) || value.foods.length > 100)
        fail("Too many foods in one day.");
      out.foods = value.foods.map((food) => {
        checkKeys(food, ["id", "name", "p", "c", "f"]);
        const name = text(food.name, 100).trim();
        if (!name) fail("Food names cannot be empty.");
        return {
          name,
          p: number(food.p, 0, 300),
          c: number(food.c, 0, 500),
          f: number(food.f, 0, 200),
        };
      });
    }
    for (const kind of ["checks", "lifts"]) {
      if (value[kind] !== undefined) {
        if (!object(value[kind]) || Object.keys(value[kind]).length > 100)
          fail("Invalid exercise log.");
        for (const [key, v] of Object.entries(value[kind])) {
          if (!/^[0-6]-\d{1,2}$/.test(key))
            fail("Invalid exercise identifier.");
          if (kind === "checks") {
            if (typeof v !== "boolean") fail("Invalid checkbox value.");
            out[kind][key] = v;
          } else out[kind][key] = text(v, 120);
        }
      }
    }
    if (value.mode !== undefined)
      out.mode = option(value.mode, ["gym", "home"]);
    if (value.effort !== undefined)
      out.effort = option(value.effort, ["normal", "low"]);
    if (value.finished !== undefined) {
      if (typeof value.finished !== "boolean")
        fail("Invalid completion value.");
      out.finished = value.finished;
    }
    for (const [key, [min, max]] of Object.entries(numeric))
      if (value[key] !== undefined && value[key] !== "")
        out[key] = number(value[key], min, max);
    for (const [key, list] of Object.entries(choices))
      if (value[key] !== undefined) out[key] = option(value[key], list);
    if (value.notes !== undefined) out.notes = text(value.notes, 1000);
    return out;
  }
  function validateBackup(raw) {
    checkKeys(raw, ["kind", "version", "exported", "settings", "logs"]);
    const legacy = raw.kind === "prep2026v2";
    if (!legacy && (raw.kind !== "fitness-planner" || raw.version !== 1))
      fail("Unsupported backup format.");
    if (!object(raw.logs) || Object.keys(raw.logs).length > 3660)
      fail("Invalid or oversized log collection.");
    const clean = {
      settings: legacy ? fresh().settings : settings(raw.settings),
      logs: {},
    };
    for (const [date, value] of Object.entries(raw.logs)) {
      if (!validDate(date)) fail("Invalid date in backup.");
      clean.logs[date] = validateLog(value);
    }
    if (legacy) {
      const dates = Object.keys(clean.logs).sort();
      if (dates.length) {
        clean.settings.start = dates[0];
        clean.settings.end = addDays(
          dates[0],
          Math.min(
            729,
            Math.max(
              41,
              Math.round((dateValue(dates.at(-1)) - dateValue(dates[0])) / DAY),
            ),
          ),
        );
      }
    }
    return clean;
  }
  function parseBackup(source) {
    if (new TextEncoder().encode(source).byteLength > MAX_FILE)
      fail("Backup must be smaller than 2 MB.");
    return validateBackup(
      JSON.parse(source, (key, value) => {
        if (["__proto__", "prototype", "constructor"].includes(key))
          fail("Unsafe field in backup.");
        return value;
      }),
    );
  }
  function backup() {
    return {
      kind: "fitness-planner",
      version: 1,
      exported: new Date().toISOString(),
      settings: state.settings,
      logs: state.logs,
    };
  }
  function save() {
    if (!remember) {
      $("storageStatus").textContent =
        "Temporary mode: entries disappear when this page closes. Export a backup to keep them.";
      return;
    }
    try {
      localStorage.setItem(STORAGE, JSON.stringify(backup()));
      $("storageStatus").textContent =
        "Saved in this browser. Your entries are not uploaded.";
    } catch {
      $("storageStatus").textContent =
        "Browser storage is unavailable or full. Export a backup to keep your entries.";
    }
  }
  function current() {
    if (!own(state.logs, selected)) state.logs[selected] = validateLog({});
    return state.logs[selected];
  }
  function hasData(log) {
    return (
      log.finished ||
      log.foods.length ||
      Object.keys(log.checks).some((k) => log.checks[k]) ||
      Object.values(log.lifts).some(Boolean) ||
      Object.keys(numeric).some((k) => own(log, k)) ||
      log.notes ||
      log.energy ||
      log.cycle
    );
  }
  function selectDate(date) {
    if (!validDate(date)) return;
    selected = date;
    $("selectedDate").value = date;
    renderAll();
  }
  function syncSettings() {
    const s = state.settings;
    $("planStart").value = s.start;
    $("planEnd").value = s.end;
    $("planGoal").value = s.goal ?? "";
    $("planCalories").value = s.calories ?? "";
  }
  function renderOverview() {
    const logs = Object.entries(state.logs).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    const weights = logs.filter(([, l]) => own(l, "weight"));
    const last = weights.at(-1);
    $("latestWeight").textContent = last
      ? last[1].weight.toFixed(1) + " kg"
      : "—";
    $("latestDate").textContent = last ? fmt(last[0]) : "No entries yet";
    $("weightGoal").textContent =
      state.settings.goal === null
        ? "—"
        : state.settings.goal.toFixed(1) + " kg";
    $("planDays").textContent =
      Math.round(
        (dateValue(state.settings.end) - dateValue(state.settings.start)) / DAY,
      ) + 1;
    $("planWindow").textContent =
      fmt(state.settings.start) + " – " + fmt(state.settings.end);
    $("sessionsDone").textContent = logs.filter(([, l]) => l.finished).length;
    $("chartEmpty").hidden = weights.length > 0;
    plot(weights);
  }
  function plot(weights) {
    const cv = $("weightChart"),
      rect = cv.getBoundingClientRect();
    if (!rect.width) return;
    const scale = Math.min(2, window.devicePixelRatio || 1);
    cv.width = Math.round(rect.width * scale);
    cv.height = Math.round(rect.height * scale);
    const c = cv.getContext("2d");
    c.scale(scale, scale);
    const style = getComputedStyle(document.documentElement),
      color = (name) => style.getPropertyValue(name).trim();
    const w = rect.width,
      h = rect.height,
      L = 48,
      R = 20,
      T = 20,
      B = 32;
    c.font = "11px system-ui";
    c.fillStyle = color("--muted");
    if (!weights.length) {
      c.fillText("Your chart will appear here.", L, 55);
      return;
    }
    const vals = weights.map(([, l]) => l.weight);
    if (state.settings.goal !== null) vals.push(state.settings.goal);
    const min = Math.min(...vals) - 1,
      max = Math.max(...vals) + 1;
    const first = dateValue(weights[0][0]),
      last = Math.max(first + DAY, dateValue(weights.at(-1)[0]));
    const x = (time) => L + ((time - first) / (last - first)) * (w - L - R),
      y = (value) => T + ((max - value) / (max - min)) * (h - T - B);
    for (let i = 0; i <= 4; i++) {
      const value = min + ((max - min) * i) / 4;
      c.strokeStyle = color("--border");
      c.beginPath();
      c.moveTo(L, y(value));
      c.lineTo(w - R, y(value));
      c.stroke();
      c.fillStyle = color("--muted");
      c.fillText(value.toFixed(1), 5, y(value) + 4);
    }
    if (state.settings.goal !== null) {
      c.setLineDash([5, 5]);
      c.strokeStyle = color("--warning");
      c.beginPath();
      c.moveTo(L, y(state.settings.goal));
      c.lineTo(w - R, y(state.settings.goal));
      c.stroke();
      c.setLineDash([]);
    }
    c.strokeStyle = color("--accent");
    c.lineWidth = 2;
    c.beginPath();
    weights.forEach(([date, log], i) => {
      const px = x(dateValue(date)),
        py = y(log.weight);
      if (i) c.lineTo(px, py);
      else c.moveTo(px, py);
    });
    c.stroke();
    for (const [date, log] of weights) {
      c.fillStyle = color("--accent");
      c.beginPath();
      c.arc(x(dateValue(date)), y(log.weight), 3, 0, Math.PI * 2);
      c.fill();
    }
    c.strokeStyle = color("--link");
    c.setLineDash([4, 3]);
    c.beginPath();
    let windowStart = 0,
      windowTotal = 0;
    weights.forEach(([date, log], i) => {
      const time = dateValue(date);
      windowTotal += log.weight;
      while (dateValue(weights[windowStart][0]) <= time - 7 * DAY) {
        windowTotal -= weights[windowStart++][1].weight;
      }
      const average = windowTotal / (i - windowStart + 1);
      const px = x(time),
        py = y(average);
      if (i) c.lineTo(px, py);
      else c.moveTo(px, py);
    });
    c.stroke();
    c.setLineDash([]);
    c.fillStyle = color("--muted");
    c.fillText(fmt(weights[0][0]), L, h - 8);
    c.textAlign = "right";
    c.fillText(fmt(weights.at(-1)[0]), w - R, h - 8);
  }
  function renderWeek() {
    const start = addDays(selected, -dayIndex(selected));
    $("weekStrip").replaceChildren(
      ...DAYS.map((name, i) => {
        const date = addDays(start, i),
          finished = state.logs[date]?.finished;
        return element(
          "button",
          {
            type: "button",
            "aria-pressed": date === selected,
            click: () => selectDate(date),
          },
          name.slice(0, 3),
          element("strong", {}, date.slice(-2)),
          finished ? "✓" : "·",
        );
      }),
    );
  }
  function renderWorkout() {
    const log = current(),
      index = dayIndex(selected),
      session = sessions[index];
    $("sessionTitle").textContent = DAYS[index] + " · " + session.title;
    $("sessionIntro").textContent = session.intro;
    $("sessionDuration").textContent = session.duration;
    $("gymMode").setAttribute("aria-pressed", String(log.mode === "gym"));
    $("homeMode").setAttribute("aria-pressed", String(log.mode === "home"));
    $("effortMode").value = log.effort;
    let completed = 0;
    $("exerciseList").replaceChildren(
      ...session.items.map((item, i) => {
        const key = index + "-" + i,
          checked = log.checks[key] === true;
        if (checked) completed++;
        const title = log.mode === "gym" ? item.gym : item.home;
        const input = element("input", {
          type: "checkbox",
          checked,
          "aria-label": "Complete " + title,
          change: (event) => {
            log.checks[key] = event.target.checked;
            save();
            renderWorkout();
          },
        });
        const load = element("input", {
          type: "text",
          maxlength: 120,
          value: log.lifts[key] || "",
          placeholder: "Load / reps",
          "aria-label": "Load and reps for " + title,
          change: (event) => {
            log.lifts[key] = event.target.value;
            save();
          },
        });
        return element(
          "div",
          { class: "exercise" + (checked ? " done" : "") },
          input,
          element(
            "div",
            {},
            element("h4", {}, title),
            element("p", {}, item.part + " · " + item.rest + " rest"),
            element("p", {}, log.mode === "gym" ? item.cue : item.homeCue),
          ),
          element(
            "div",
            { class: "exercise-sets" },
            `${log.effort === "low" ? Math.max(1, Math.ceil(item.sets / 2)) : item.sets} × ${log.mode === "gym" ? item.reps : item.homeReps}`,
          ),
          element("label", {}, "Your session", load),
        );
      }),
    );
    $("exerciseProgress").textContent =
      completed + " / " + session.items.length + " exercises checked";
    $("finishWorkout").textContent = log.finished
      ? "Session complete ✓ · Undo"
      : "Mark session complete";
    $("finishWorkout").setAttribute("aria-pressed", String(log.finished));
  }
  function foodFromMeal(meal) {
    return { name: meal[1], p: meal[3], c: meal[4], f: meal[5] };
  }
  function appendFoods(foods) {
    const log = current();
    if (log.foods.length + foods.length > 100) {
      toast("Maximum 100 food entries per day.");
      return;
    }
    log.foods.push(...foods);
    save();
    renderFood();
    renderHistory();
    toast("Added to " + fmt(selected));
  }
  function renderMeals() {
    $("mealCards").replaceChildren(
      ...meals[mealDay].map((meal) => {
        const food = foodFromMeal(meal);
        return element(
          "article",
          { class: "card" },
          element("span", { class: "meal-type" }, meal[0]),
          element("h3", {}, meal[1]),
          element("p", {}, meal[2]),
          element(
            "div",
            { class: "meal-macros" },
            `${calories(food)} kcal · P ${food.p} g · C ${food.c} g · F ${food.f} g`,
          ),
          element("p", {}, meal[6]),
          element(
            "button",
            { type: "button", click: () => appendFoods([food]) },
            "Add to selected day",
          ),
        );
      }),
    );
    const total = totals(meals[mealDay].map(foodFromMeal));
    $("mealTotals").textContent =
      `Sample total: ${calories(total)} kcal · Protein ${total.p} g · Carbs ${total.c} g · Fat ${total.f} g`;
  }
  function renderQuickFoods() {
    $("quickFood").replaceChildren(
      ...quickFoods[$("foodGroup").value].map((food, i) =>
        element("option", { value: i }, food[0]),
      ),
    );
    renderQuickPreview();
  }
  function quickSelection() {
    const food =
        quickFoods[$("foodGroup").value]?.[Number($("quickFood").value)],
      qty = Number($("quickQty").value);
    if (!food || !Number.isFinite(qty) || qty < 0.25 || qty > 8) return null;
    return {
      name: (food[0] + " × " + qty).slice(0, 100),
      p: Math.round(food[1] * qty * 100) / 100,
      c: Math.round(food[2] * qty * 100) / 100,
      f: Math.round(food[3] * qty * 100) / 100,
    };
  }
  function renderQuickPreview() {
    const food = quickSelection();
    $("quickPreview").textContent = food
      ? `${calories(food)} kcal · Protein ${food.p} g · Carbs ${food.c} g · Fat ${food.f} g`
      : "Choose a valid serving count.";
  }
  function renderFields() {
    const log = current();
    $("logDate").textContent = fmt(selected);
    document
      .querySelectorAll("[data-log]")
      .forEach((input) => (input.value = log[input.dataset.log] ?? ""));
  }
  function renderFood() {
    const log = current(),
      sum = totals(log.foods);
    $("foodRows").replaceChildren(
      ...(log.foods.length
        ? log.foods.map((food, i) =>
            element(
              "tr",
              {},
              element("td", {}, food.name),
              ...[
                calories(food),
                food.p.toFixed(1) + " g",
                food.c.toFixed(1) + " g",
                food.f.toFixed(1) + " g",
              ].map((v) => element("td", {}, v)),
              element(
                "td",
                {},
                element(
                  "button",
                  {
                    type: "button",
                    "aria-label": "Remove " + food.name,
                    click: () => {
                      log.foods.splice(i, 1);
                      save();
                      renderFood();
                      renderHistory();
                    },
                  },
                  "Remove",
                ),
              ),
            ),
          )
        : [
            element(
              "tr",
              {},
              element("td", { colspan: 6 }, "No food entries yet."),
            ),
          ]),
    );
    $("foodTotals").textContent =
      `${calories(sum)} kcal · Protein ${sum.p.toFixed(1)} g · Carbs ${sum.c.toFixed(1)} g · Fat ${sum.f.toFixed(1)} g`;
    $("calorieReference").textContent =
      state.settings.calories === null
        ? "No daily calorie reference set."
        : `Your optional reference: ${state.settings.calories} kcal. Logged: ${calories(sum)} kcal.`;
  }
  function renderHistory() {
    const rows = Object.entries(state.logs)
      .filter(([, l]) => hasData(l))
      .sort(([a], [b]) => b.localeCompare(a));
    $("historyRows").replaceChildren(
      ...(rows.length
        ? rows.map(([date, log]) => {
            const total = totals(log.foods);
            return element(
              "tr",
              {},
              ...[
                fmt(date),
                own(log, "weight") ? log.weight + " kg" : "—",
                own(log, "waist") ? log.waist + " cm" : "—",
                log.foods.length ? calories(total) : "—",
                log.foods.length ? total.p.toFixed(1) + " g" : "—",
                log.finished ? "Complete" : "—",
                own(log, "sleep") ? log.sleep + " h" : "—",
              ].map((v) => element("td", {}, v)),
            );
          })
        : [
            element(
              "tr",
              {},
              element("td", { colspan: 7 }, "Your check-ins will appear here."),
            ),
          ]),
    );
  }
  function renderLibrary() {
    $("exerciseLibrary").replaceChildren(
      ...sessions.map((session, i) =>
        element(
          "div",
          {},
          element("h3", {}, DAYS[i] + " · " + session.title),
          element(
            "ul",
            {},
            session.items.map((item) =>
              element(
                "li",
                {},
                `${item.gym} → ${item.home} · ${item.sets} sets · ${item.part}`,
              ),
            ),
          ),
        ),
      ),
    );
  }
  function renderAll() {
    renderWeek();
    renderWorkout();
    renderFields();
    renderFood();
    renderHistory();
    renderOverview();
  }
  function download(content, type, name) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const a = element("a", { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function csvCell(value) {
    let s = String(value ?? "");
    if (typeof value === "string" && /^[\s\uFEFF]*[=+\-@＝＋－＠]/u.test(s))
      s = "Text: " + s;
    return '"' + s.replaceAll('"', '""') + '"';
  }
  function csv() {
    const rows = [
      [
        "date",
        "weight_kg",
        "waist_cm",
        "sleep_h",
        "steps",
        "energy",
        "cycle",
        "practice_min",
        "calories",
        "protein_g",
        "carbs_g",
        "fat_g",
        "workout_completed",
        "venue",
        "recovery",
        "notes",
      ],
    ];
    for (const [date, log] of Object.entries(state.logs).sort(([a], [b]) =>
      a.localeCompare(b),
    )) {
      if (!hasData(log)) continue;
      const t = totals(log.foods);
      rows.push([
        date,
        log.weight ?? "",
        log.waist ?? "",
        log.sleep ?? "",
        log.steps ?? "",
        log.energy ?? "",
        log.cycle ?? "",
        log.posing ?? "",
        log.foods.length ? calories(t) : "",
        log.foods.length ? t.p : "",
        log.foods.length ? t.c : "",
        log.foods.length ? t.f : "",
        log.finished ? "yes" : "no",
        log.mode,
        log.effort,
        log.notes ?? "",
      ]);
    }
    return rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
  }
  try {
    remember = localStorage.getItem(REMEMBER) !== "false";
    const stored = remember ? localStorage.getItem(STORAGE) : null;
    if (stored) state = parseBackup(stored);
  } catch {
    toast(
      "Stored data could not be read. A fresh session is open; import a valid backup to restore.",
    );
  }
  $("rememberData").checked = remember;
  syncSettings();
  $("selectedDate").value = selected;
  $("selectedDate").addEventListener("change", (e) => {
    if (validDate(e.target.value)) selectDate(e.target.value);
    else {
      e.target.value = selected;
      toast("Choose a valid date.");
    }
  });
  $("settingsForm").addEventListener("submit", (event) => {
    event.preventDefault();
    try {
      state.settings = settings({
        start: $("planStart").value,
        end: $("planEnd").value,
        goal: $("planGoal").value,
        calories: $("planCalories").value,
      });
      save();
      renderOverview();
      renderFood();
      toast("Plan settings saved.");
    } catch (error) {
      toast(error.message);
    }
  });
  $("rememberData").addEventListener("change", (event) => {
    remember = event.target.checked;
    let storageError = false;
    try {
      if (!remember) localStorage.removeItem(STORAGE);
      localStorage.setItem(REMEMBER, String(remember));
    } catch {
      storageError = true;
      toast(
        "Browser storage could not be changed. Check this browser's site data to remove previously saved entries.",
      );
    }
    save();
    if (storageError)
      $("storageStatus").textContent =
        "Storage settings could not be updated. Previously saved entries may remain in this browser.";
  });
  $("clearData").addEventListener("click", () => {
    if (
      !confirm(
        "Delete all saved fitness entries and reset plan settings? Export a backup first if needed.",
      )
    )
      return;
    let removalFailed = false;
    try {
      localStorage.removeItem(STORAGE);
    } catch {
      removalFailed = true;
    }
    state = fresh();
    selected = localToday();
    syncSettings();
    selectDate(selected);
    save();
    toast(
      removalFailed
        ? "This session was cleared, but browser storage could not be removed. Clear this browser's site data to remove saved entries."
        : "Fitness data cleared.",
    );
  });
  for (const mode of ["gym", "home"])
    $(mode + "Mode").addEventListener("click", () => {
      current().mode = mode;
      save();
      renderWorkout();
    });
  $("effortMode").addEventListener("change", (e) => {
    current().effort = e.target.value;
    save();
    renderWorkout();
  });
  $("finishWorkout").addEventListener("click", () => {
    current().finished = !current().finished;
    save();
    renderWorkout();
    renderWeek();
    renderOverview();
    renderHistory();
  });
  $("clearExercises").addEventListener("click", () => {
    if (!confirm("Clear exercise checks for this date?")) return;
    current().checks = {};
    save();
    renderWorkout();
  });
  $("mealDay").replaceChildren(
    ...DAYS.map((day, i) => element("option", { value: i }, day)),
  );
  $("mealDay").value = mealDay;
  $("mealDay").addEventListener("change", (e) => {
    mealDay = Number(e.target.value);
    renderMeals();
  });
  $("addAllMeals").addEventListener("click", () => {
    if (confirm("Add all four sample meals to " + fmt(selected) + "?"))
      appendFoods(meals[mealDay].map(foodFromMeal));
  });
  $("foodGroup").addEventListener("change", renderQuickFoods);
  $("quickFood").addEventListener("change", renderQuickPreview);
  $("quickQty").addEventListener("input", renderQuickPreview);
  $("quickAdd").addEventListener("click", () => {
    const food = quickSelection();
    if (!food) {
      toast("Choose a valid serving count.");
      return;
    }
    try {
      validateLog({ foods: [food] });
      appendFoods([food]);
    } catch (error) {
      toast(error.message);
    }
  });
  document.querySelectorAll("[data-log]").forEach((input) =>
    input.addEventListener("change", () => {
      const key = input.dataset.log;
      try {
        let value = input.value;
        if (own(numeric, key)) {
          if (value === "") {
            delete current()[key];
          } else current()[key] = number(value, ...numeric[key]);
        } else if (own(choices, key))
          current()[key] = option(value, choices[key]);
        else current()[key] = text(value, 1000);
        save();
        renderHistory();
        renderOverview();
      } catch (error) {
        input.value = current()[key] ?? "";
        toast(error.message);
      }
    }),
  );
  $("foodForm").addEventListener("submit", (event) => {
    event.preventDefault();
    try {
      const food = {
        name: $("foodName").value.trim(),
        p: Number($("foodProtein").value),
        c: Number($("foodCarbs").value),
        f: Number($("foodFat").value),
      };
      validateLog({ foods: [food] });
      appendFoods([food]);
      event.target.reset();
    } catch (error) {
      toast(error.message);
    }
  });
  $("clearFood").addEventListener("click", () => {
    if (confirm("Remove food entries for " + fmt(selected) + "?")) {
      current().foods = [];
      save();
      renderFood();
      renderHistory();
    }
  });
  $("exportData").addEventListener("click", () => {
    download(
      JSON.stringify(backup(), null, 2),
      "application/json",
      "fitness-backup.json",
    );
    toast("Backup downloaded. It contains your entered personal data.");
  });
  $("exportCSV").addEventListener("click", () => {
    download(csv(), "text/csv;charset=utf-8", "fitness-daily-log.csv");
    toast("CSV downloaded. It contains your entered personal data.");
  });
  $("importData").addEventListener("click", () => $("importFile").click());
  $("importFile").addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      if (file.size > MAX_FILE) fail("Backup must be smaller than 2 MB.");
      const candidate = parseBackup(await file.text());
      if (
        !confirm(
          "Replace the current fitness entries and settings with this validated backup?",
        )
      )
        return;
      state = candidate;
      selected = state.settings.start;
      syncSettings();
      save();
      selectDate(selected);
      toast("Backup imported.");
    } catch (error) {
      toast("Import rejected: " + error.message);
    } finally {
      event.target.value = "";
    }
  });
  $("printPlanner").addEventListener("click", () => window.print());
  let resizePending = false;
  function redraw() {
    if (resizePending) return;
    resizePending = true;
    requestAnimationFrame(() => {
      resizePending = false;
      renderOverview();
    });
  }
  window.addEventListener("resize", redraw, { passive: true });
  window.addEventListener("themechange", redraw);
  renderMeals();
  renderQuickFoods();
  renderLibrary();
  renderAll();
  if (remember) {
    $("storageStatus").textContent =
      "Your entries stay in this browser. They are not uploaded.";
  } else save();
})();
