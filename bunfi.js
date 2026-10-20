"use strict";

const STORAGE_KEY = "cwe-training-lab-progress-v1";

const challenges = [
  {
    id: "sqli",
    title: "SQL Injection",
    cwe: "CWE-89",
    points: 20,
    scenarioTitle: "Demo Login Page",
    scenarioDescription:
      "Try regular input and attack-style input on the left. You then fix the code on the right.",
    hint: "Do not build SQL with string concatenation. Use parameterized queries and avoid comparing raw passwords.",
    vulnerableCode: `# Vulnerable Python login handler\ndef login(username, password, db):\n    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"\n    result = db.execute(query)\n    return len(result) > 0\n`,
    secureCode: `# Safer Python login handler\ndef login(username, password, db):\n    query = "SELECT * FROM users WHERE username = %s"\n    user = db.fetch_one(query, [username])\n    return bool(user and verify_password(user.password_hash, password))\n`,
    check(code) {
      return (
        !/\+\s*username|username\s*\+|\+\s*password|password\s*\+/i.test(
          code,
        ) &&
        /(?:execute|fetch_one)\s*\(\s*query\s*,/i.test(code) &&
        /verify_password|check_password_hash/i.test(code)
      );
    },
    renderWebsite() {
      return `
            <div class="mini-bar"><span>🔐 SecureBank Portal</span><span>Login</span></div>
            <label for="loginUser">Username</label>
            <input id="loginUser" value="admin" />
            <label for="loginPass" style="margin-top:12px;">Password</label>
            <input id="loginPass" value="wrong-password" />
            <div class="btn-row">
              <button class="primary" data-action="runSQLiDemo">Sign in</button>
              <button class="secondary" data-action="loadSQLiAttack">Try attack payload</button>
            </div>
            <div class="result-box" id="loginResult">Try the login form.</div>
          `;
    },
    bindWebsite() {},
  },
  {
    id: "xss",
    title: "Cross-Site Scripting",
    cwe: "CWE-79",
    points: 20,
    scenarioTitle: "Comment Widget",
    scenarioDescription:
      "Students can compare unsafe rendering and safe rendering without executing scripts.",
    hint: "Avoid innerHTML for untrusted input. Prefer textContent or a trusted sanitizer when HTML is truly needed.",
    vulnerableCode: `// Vulnerable JavaScript comment preview\nfunction renderComment(input) {\n  document.getElementById('preview').innerHTML = input;\n}\n`,
    secureCode: `// Safer JavaScript comment preview\nfunction renderComment(input) {\n  document.getElementById('preview').textContent = input;\n}\n`,
    check(code) {
      return (
        !/innerHTML/i.test(code) &&
        /textContent|createTextNode|sanitize/i.test(code)
      );
    },
    renderWebsite() {
      return `
            <div class="mini-bar"><span>💬 Team Comments</span><span>Preview</span></div>
            <label for="xssInput">Comment</label>
            <textarea id="xssInput">Hello team, this looks great.</textarea>
            <div class="btn-row">
              <button class="secondary" data-action="setXSSMode" data-mode="unsafe">Unsafe view</button>
              <button class="primary" data-action="setXSSMode" data-mode="safe">Safe view</button>
              <button class="secondary" data-action="loadXSSPayload">Try payload</button>
            </div>
            <div class="result-box">
              <strong>Preview</strong>
              <div class="preview-box" id="xssPreview"></div>
            </div>
          `;
    },
    bindWebsite() {
      setXSSMode("safe");
      document
        .getElementById("xssInput")
        .addEventListener("input", renderXSSPreview);
    },
  },
  {
    id: "idor",
    title: "Broken Access Control",
    cwe: "CWE-639",
    points: 20,
    scenarioTitle: "Invoice Portal",
    scenarioDescription:
      "Change the logged-in user and invoice ID to see the difference between insecure and secure behavior.",
    hint: "Check ownership or authorization on every object fetch. Do not trust user-controlled identifiers alone.",
    vulnerableCode: `# Vulnerable Flask-like route\n@app.get('/invoice/<invoice_id>')\ndef get_invoice(invoice_id):\n    invoice = db.find_invoice(invoice_id)\n    return invoice\n`,
    secureCode: `# Safer Flask-like route\n@app.get('/invoice/<invoice_id>')\ndef get_invoice(invoice_id, current_user):\n    invoice = db.find_invoice(invoice_id)\n    if not invoice or invoice.owner_id != current_user.id:\n        return {"error": "forbidden"}, 403\n    return invoice\n`,
    check(code) {
      return (
        /current_user|user/i.test(code) &&
        /owner_id|user_id|authorize|permission|403|forbidden/i.test(code)
      );
    },
    renderWebsite() {
      return `
            <div class="mini-bar"><span>🧾 Billing Portal</span><span>Invoices</span></div>
            <div class="row-2">
              <div>
                <label for="idorUser">Logged in as</label>
                <select id="idorUser" data-change="idor">
                  <option value="alice">alice</option>
                  <option value="bob">bob</option>
                </select>
              </div>
              <div>
                <label for="idorInvoice">Invoice ID</label>
                <select id="idorInvoice" data-change="idor">
                  <option value="INV-1001">INV-1001</option>
                  <option value="INV-1002">INV-1002</option>
                  <option value="INV-1003">INV-1003</option>
                </select>
              </div>
            </div>
            <div class="row-2" style="margin-top:14px;">
              <div class="result-box"><strong>Vulnerable output</strong><div id="idorUnsafe" style="margin-top:8px;"></div></div>
              <div class="result-box"><strong>Secure output</strong><div id="idorSafe" style="margin-top:8px;"></div></div>
            </div>
          `;
    },
    bindWebsite() {
      renderIDORDemo();
    },
  },
  {
    id: "csrf",
    title: "CSRF",
    cwe: "CWE-352",
    points: 20,
    scenarioTitle: "Profile Settings",
    scenarioDescription:
      "Students can see why a state-changing form needs anti-CSRF validation.",
    hint: "Include and validate an anti-CSRF token on state-changing requests. Cookie settings help, but are not enough alone.",
    vulnerableCode: `# Vulnerable state-changing handler\n@app.post('/update-email')\ndef update_email(request, current_user):\n    current_user.email = request.form['email']\n    db.save(current_user)\n    return 'ok'\n`,
    secureCode: `# Safer state-changing handler\n@app.post('/update-email')\ndef update_email(request, current_user):\n    verify_csrf(request.form['csrf_token'], request.session)\n    current_user.email = request.form['email']\n    db.save(current_user)\n    return 'ok'\n`,
    check(code) {
      return /csrf/i.test(code) && /verify|validate|check/i.test(code);
    },
    renderWebsite() {
      return `
            <div class="mini-bar"><span>⚙️ Account Settings</span><span>Profile</span></div>
            <label for="csrfEmail">New email</label>
            <input id="csrfEmail" value="alice@example.com" />
            <div style="margin-top:12px;">
              <label><input type="checkbox" id="csrfTokenBox" /> Include CSRF token</label>
            </div>
            <div class="btn-row">
              <button class="primary" data-action="runCSRFDemo">Save profile</button>
              <button class="secondary" data-action="enableCSRFSecure">Use secure mode</button>
            </div>
            <div class="result-box" id="csrfResult">Waiting for update.</div>
          `;
    },
    bindWebsite() {},
  },
  {
    id: "path",
    title: "Path Traversal",
    cwe: "CWE-22",
    points: 20,
    scenarioTitle: "Reports Download Center",
    scenarioDescription:
      "Try normal filenames and traversal-style input to explain why server-side file handling matters.",
    hint: "Do not concatenate a path with user input. Normalize the path and constrain it to a safe base directory or allowlist.",
    vulnerableCode: `# Vulnerable download handler\ndef download(filename):\n    path = '/app/reports/' + filename\n    return open(path).read()\n`,
    secureCode: `# Safer download handler\nfrom pathlib import Path\n\nBASE = Path('/app/reports').resolve()\n\ndef download(filename):\n    safe_name = Path(filename).name\n    path = (BASE / safe_name).resolve()\n    if BASE not in path.parents and path != BASE:\n        return 'forbidden', 403\n    return open(path).read()\n`,
    check(code) {
      return (
        !/\+\s*filename|filename\s*\+/i.test(code) &&
        /Path\(|basename|allowlist|resolve/i.test(code) &&
        /403|forbidden|deny/i.test(code)
      );
    },
    renderWebsite() {
      return `
            <div class="mini-bar"><span>📁 Reports Center</span><span>Downloads</span></div>
            <label for="pathInput">Requested file name</label>
            <input id="pathInput" value="report-q1.pdf" />
            <div class="btn-row">
              <button class="primary" data-action="runPathDemo">Download</button>
              <button class="secondary" data-action="loadPathPayload">Try traversal input</button>
            </div>
            <div class="row-2">
              <div class="result-box"><strong>Vulnerable path</strong><div id="pathUnsafe" style="margin-top:8px;"></div></div>
              <div class="result-box"><strong>Secure handling</strong><div id="pathSafe" style="margin-top:8px;"></div></div>
            </div>
          `;
    },
    bindWebsite() {
      runPathDemo();
    },
  },
];

let state = loadState();
let currentId = state.currentId || challenges[0].id;

function defaultState() {
  const byId = {};
  challenges.forEach((ch) => {
    byId[ch.id] = {
      code: ch.vulnerableCode,
      solved: false,
      attempts: 0,
      hintShown: false,
    };
  });
  return { currentId: challenges[0].id, byId };
}

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultState();
    const parsed = JSON.parse(raw);
    const fresh = defaultState();
    for (const ch of challenges) {
      if (parsed.byId && parsed.byId[ch.id]) {
        fresh.byId[ch.id] = {
          ...fresh.byId[ch.id],
          code:
            typeof parsed.byId[ch.id].code === "string"
              ? parsed.byId[ch.id].code.slice(0, 20000)
              : ch.vulnerableCode,
          solved: parsed.byId[ch.id].solved === true,
          attempts: Number.isSafeInteger(parsed.byId[ch.id].attempts)
            ? Math.max(0, Math.min(10000, parsed.byId[ch.id].attempts))
            : 0,
          hintShown: parsed.byId[ch.id].hintShown === true,
        };
      }
    }
    fresh.currentId = challenges.some((ch) => ch.id === parsed.currentId)
      ? parsed.currentId
      : fresh.currentId;
    return fresh;
  } catch {
    return defaultState();
  }
}

function saveState() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    document.querySelector(".footer-note").textContent =
      "Browser storage unavailable. Progress will last for this visit.";
  }
}

function currentChallenge() {
  return challenges.find((ch) => ch.id === currentId);
}

function totalPoints() {
  return challenges.reduce(
    (sum, ch) => sum + (state.byId[ch.id].solved ? ch.points : 0),
    0,
  );
}

function progressLabel(score) {
  if (score === 100) return "All challenges fixed";
  if (score >= 60) return "Good progress";
  if (score >= 20) return "Getting started";
  return "New session";
}

function renderTabs() {
  const wrap = document.getElementById("challengeTabs");
  wrap.innerHTML = challenges
    .map(
      (ch) => `
        <button class="tab ${ch.id === currentId ? "active" : ""}" data-challenge="${ch.id}" aria-pressed="${ch.id === currentId}">
          <div style="font-weight:700; margin-bottom:4px;">${ch.title}</div>
          <div class="muted" style="font-size:12px;">${ch.cwe}</div>
        </button>
      `,
    )
    .join("");
}

function renderScoreboard() {
  const list = document.getElementById("scoreList");
  list.innerHTML = challenges
    .map((ch) => {
      const solved = state.byId[ch.id].solved;
      return `
          <div class="score-item">
            <div>
              <div style="font-weight:700;">${ch.title}</div>
              <div class="muted" style="font-size:12px;">${ch.cwe}</div>
            </div>
            <span class="score-status ${solved ? "solved" : "pending"}">${solved ? "Solved" : ch.points + " pts"}</span>
          </div>
        `;
    })
    .join("");

  const points = totalPoints();
  document.getElementById("progressLabel").textContent =
    `${points}/100 · ${progressLabel(points)}`;
  document.getElementById("progressFill").style.width = `${points}%`;
}

function renderChallenge() {
  const ch = currentChallenge();
  state.currentId = currentId;
  saveState();

  renderTabs();
  renderScoreboard();

  document.getElementById("scenarioTitle").textContent = ch.scenarioTitle;
  document.getElementById("scenarioDescription").textContent =
    ch.scenarioDescription;
  document.getElementById("scenarioBadge").textContent = `${ch.cwe}`;
  document.getElementById("pointsBadge").textContent = `${ch.points} points`;
  document.getElementById("codeEditor").value = state.byId[ch.id].code;
  document.getElementById("attemptsText").textContent =
    `Attempts: ${state.byId[ch.id].attempts}`;

  const hintBox = document.getElementById("hintBox");
  if (state.byId[ch.id].hintShown) {
    hintBox.innerHTML = `<div class="hint-box"><strong>Hint:</strong> ${escapeHtml(ch.hint)}</div>`;
  } else {
    hintBox.innerHTML = "";
  }

  const website = document.getElementById("websitePanel");
  website.innerHTML = ch.renderWebsite();
  if (typeof ch.bindWebsite === "function") ch.bindWebsite();
}

function selectChallenge(id) {
  if (!challenges.some((ch) => ch.id === id)) return;
  syncEditorToState();
  currentId = id;
  renderChallenge();
}

function syncEditorToState() {
  const editor = document.getElementById("codeEditor");
  if (!editor) return;
  state.byId[currentId].code = editor.value.slice(0, 20000);
  saveState();
}

let modalPreviousFocus;
function showModal(title, text) {
  modalPreviousFocus = document.activeElement;
  document.getElementById("modalTitle").textContent = title;
  document.getElementById("modalText").textContent = text;
  document.getElementById("modal").classList.add("show");
  document.getElementById("modalClose").focus();
}

function hideModal() {
  document.getElementById("modal").classList.remove("show");
  modalPreviousFocus?.focus();
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function checkFix() {
  syncEditorToState();
  const ch = currentChallenge();
  const code = state.byId[ch.id].code;
  state.byId[ch.id].attempts += 1;
  const ok = ch.check(code);

  if (ok) {
    const firstSolve = !state.byId[ch.id].solved;
    state.byId[ch.id].solved = true;
    saveState();
    renderScoreboard();
    document.getElementById("attemptsText").textContent =
      `Attempts: ${state.byId[ch.id].attempts}`;
    showModal(
      "Nice work",
      firstSolve
        ? `You fixed ${ch.title} and earned ${ch.points} points.`
        : `This challenge is already solved. Good job reviewing it again.`,
    );
  } else {
    saveState();
    document.getElementById("attemptsText").textContent =
      `Attempts: ${state.byId[ch.id].attempts}`;
    showModal(
      "Try again",
      "That fix is not complete yet. Use the hint or compare your code to a safer pattern.",
    );
  }
}

function showHint() {
  const ch = currentChallenge();
  state.byId[ch.id].hintShown = true;
  saveState();
  document.getElementById("hintBox").innerHTML =
    `<div class="hint-box"><strong>Hint:</strong> ${escapeHtml(ch.hint)}</div>`;
}

function showSolution() {
  const ch = currentChallenge();
  state.byId[ch.id].code = ch.secureCode;
  saveState();
  document.getElementById("codeEditor").value = ch.secureCode;
}

function resetChallenge() {
  const ch = currentChallenge();
  state.byId[ch.id].code = ch.vulnerableCode;
  state.byId[ch.id].hintShown = false;
  saveState();
  renderChallenge();
}

function resetAll() {
  if (!confirm("Reset all progress and code edits?")) return;
  state = defaultState();
  currentId = state.currentId;
  saveState();
  renderChallenge();
}

document.getElementById("fixedBtn").addEventListener("click", checkFix);
document.getElementById("hintBtn").addEventListener("click", showHint);
document.getElementById("solutionBtn").addEventListener("click", showSolution);
document.getElementById("resetBtn").addEventListener("click", resetChallenge);
document.getElementById("resetAllBtn").addEventListener("click", resetAll);
document.getElementById("modalClose").addEventListener("click", hideModal);
document.getElementById("modal").addEventListener("click", (e) => {
  if (e.target.id === "modal") hideModal();
});
document
  .getElementById("codeEditor")
  .addEventListener("input", syncEditorToState);

function runSQLiDemo() {
  const username = document.getElementById("loginUser").value;
  const password = document.getElementById("loginPass").value;
  const suspicious =
    /'|--|\bor\b|\b1=1\b/i.test(username) ||
    /'|--|\bor\b|\b1=1\b/i.test(password);
  const result = document.getElementById("loginResult");
  if (suspicious) {
    result.innerHTML =
      "<strong>Vulnerable result:</strong> This  demo treats the input as a likely login bypass when the query is built by string concatenation.";
  } else if (username === "admin" && password === "summer2026") {
    result.innerHTML = "<strong>Result:</strong> Valid login.";
  } else {
    result.innerHTML = "<strong>Result:</strong> Login failed.";
  }
}

function loadSQLiAttack() {
  document.getElementById("loginUser").value = "admin' OR '1'='1";
  document.getElementById("loginPass").value = "anything";
  runSQLiDemo();
}

let xssMode = "safe";
function setXSSMode(mode) {
  xssMode = mode;
  renderXSSPreview();
}

function loadXSSPayload() {
  document.getElementById("xssInput").value = "<img src=x onerror=alert(1)>";
  renderXSSPreview();
}

function renderXSSPreview() {
  const value = document.getElementById("xssInput").value;
  const preview = document.getElementById("xssPreview");
  const suspicious = /<script|onerror=|onload=|<img|<svg|javascript:/i.test(
    value,
  );
  if (xssMode === "unsafe") {
    preview.innerHTML = suspicious
      ? '<span style="color:var(--warning);">Unsafe renderer would treat this as HTML-capable input in a vulnerable app.</span>'
      : '<span style="color:var(--muted);">Unsafe renderer would insert this directly with innerHTML.</span>';
  } else {
    preview.innerHTML = `<div class="safe-text"></div>`;
    preview.querySelector(".safe-text").textContent = value;
  }
}

function renderIDORDemo() {
  const invoices = {
    "INV-1001": { owner: "alice", amount: "$120" },
    "INV-1002": { owner: "bob", amount: "$450" },
    "INV-1003": { owner: "alice", amount: "$980" },
  };
  const user = document.getElementById("idorUser").value;
  const invoiceId = document.getElementById("idorInvoice").value;
  const invoice = invoices[invoiceId];
  document.getElementById("idorUnsafe").textContent = invoice
    ? `${invoice.amount} for ${invoice.owner}`
    : "Invoice not found";
  document.getElementById("idorSafe").textContent = invoice
    ? invoice.owner === user
      ? `${invoice.amount} for ${invoice.owner}`
      : "403 Forbidden"
    : "Invoice not found";
}

function runCSRFDemo() {
  const email = document.getElementById("csrfEmail").value;
  const hasToken = document.getElementById("csrfTokenBox").checked;
  const result = document.getElementById("csrfResult");
  if (hasToken) {
    result.innerHTML = `<strong>Secure flow:</strong> Email updated to ${escapeHtml(email)} because the request includes a token to validate.`;
  } else {
    result.innerHTML =
      "<strong>Vulnerable flow:</strong> This state-changing request is forgeable because no CSRF token was verified.";
  }
}

function enableCSRFSecure() {
  document.getElementById("csrfTokenBox").checked = true;
  runCSRFDemo();
}

function loadPathPayload() {
  document.getElementById("pathInput").value = "../../etc/passwd";
  runPathDemo();
}

function runPathDemo() {
  const filename = document.getElementById("pathInput").value;
  const suspicious = /\.\.|\//.test(filename);
  document.getElementById("pathUnsafe").textContent =
    `/app/reports/${filename}`;
  document.getElementById("pathSafe").textContent = suspicious
    ? "Reject request or normalize it against a safe allowlist and base directory."
    : "Normalize the name and constrain it to the reports directory.";
}

renderChallenge();

const actions = {
  runSQLiDemo,
  loadSQLiAttack,
  loadXSSPayload,
  runCSRFDemo,
  enableCSRFSecure,
  runPathDemo,
  loadPathPayload,
};
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action],[data-challenge]");
  if (!button) return;
  if (button.dataset.challenge) selectChallenge(button.dataset.challenge);
  else if (button.dataset.action === "setXSSMode")
    setXSSMode(button.dataset.mode === "unsafe" ? "unsafe" : "safe");
  else if (Object.hasOwn(actions, button.dataset.action))
    actions[button.dataset.action]();
});
document.addEventListener("change", (event) => {
  if (event.target.matches('[data-change="idor"]')) renderIDORDemo();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") hideModal();
});

document.addEventListener("keydown", (event) => {
  if (
    event.key === "Tab" &&
    document.getElementById("modal").classList.contains("show")
  ) {
    event.preventDefault();
    document.getElementById("modalClose").focus();
  }
});
