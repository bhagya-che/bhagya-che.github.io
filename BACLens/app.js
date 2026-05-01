import { AC_RULES, CWE_RULES } from "./analyzer_package/index.js";

/* ========================= HELPERS ========================= */
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"]/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;'
  }[c]));
}

function renderCodeWithLineNumbers(code, startLine = 1) {
  const lines = String(code ?? '').split('\n');

  return `
    <div class="numbered-code-block">
      ${lines.map((line, index) => `
        <div class="code-line">
          <span class="line-number">${startLine + index}</span>
          <span class="line-content">${escapeHtml(line) || ' '}</span>
        </div>
      `).join('')}
    </div>
  `;
}

function reFlags() { return 'gim'; }

function compilePattern(p) {
  try {
    return new RegExp(p, 'gim');
  } catch (e) {
    return null;
  }
}

function anyMatch(patterns, text) {
  for (const p of patterns) {
    const r = compilePattern(p);
    if (r && r.test(text)) return true;
  }
  return false;
}

function findMatches(patterns, text) {
  const out = [];
  for (const p of patterns) {
    const r = compilePattern(p);
    if (!r) continue;

    let m;
    while ((m = r.exec(text)) !== null) {
      const snippet = m[0].replace(/\s+/g, ' ').trim().slice(0, 240);
      if (snippet && !out.includes(snippet)) out.push(snippet);
      if (m.index === r.lastIndex) r.lastIndex++;
    }
  }
  return out;
}

function lineNumber(text, offset) {
  let n = 1;
  for (let i = 0; i < offset; i++) {
    if (text[i] === '\n') n++;
  }
  return n;
}

function boundedWindow(text, start, end, windowLines) {
  const lines = text.split('\n');
  if (!lines.length) return [text, 1, 1];

  const startLine = lineNumber(text, start);
  const endLine = lineNumber(text, end);
  const lo = Math.max(1, startLine - windowLines);
  const hi = Math.min(lines.length, endLine + windowLines);

  return [lines.slice(lo - 1, hi).join('\n'), lo, hi];
}

function hasAntipattern(antiPatterns, text) {
  for (const p of antiPatterns) {
    const r = compilePattern(p);
    if (r && r.test(text)) return true;
  }
  return false;
}

/* ========================= PARSERS ========================= */
function parseMarkdown(md) {
  const sections = [];
  const lines = md.split('\n');

  let current = {
    heading: 'Untitled',
    level: 0,
    codeBlocks: [],
    textLines: []
  };

  let inCode = false;
  let codeLang = '';
  let codeBuffer = [];

  function flushCode() {
    if (codeBuffer.length) {
      current.codeBlocks.push({
        lang: codeLang,
        code: codeBuffer.join('\n')
      });
      codeBuffer = [];
    }
  }

  function flushSection() {
    flushCode();
    if (current.codeBlocks.length || current.textLines.length) {
      sections.push({ ...current });
    }
  }

  for (let line of lines) {
    const hMatch = line.match(/^(#{1,6})\s+(.*)$/);

    if (hMatch) {
      flushSection();
      current = {
        heading: hMatch[2].trim(),
        level: hMatch[1].length,
        codeBlocks: [],
        textLines: []
      };
      continue;
    }

    const codeFence = line.match(/^```(.*)$/);

    if (codeFence) {
      if (inCode) {
        flushCode();
        inCode = false;
        codeLang = '';
      } else {
        inCode = true;
        codeLang = codeFence[1].trim();
      }
      continue;
    }

    if (inCode) {
      codeBuffer.push(line);
    } else {
      current.textLines.push(line);
    }
  }

  flushSection();
  return sections;
}

function parseHTML(html) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');
  const sections = [];

  const walker = doc.createTreeWalker(doc.body, NodeFilter.SHOW_ELEMENT);

  let current = {
    heading: 'Untitled',
    level: 0,
    codeBlocks: [],
    textLines: []
  };

  let node;

  while ((node = walker.nextNode())) {
    const tag = node.tagName.toLowerCase();

    if (/^h[1-6]$/.test(tag)) {
      if (current.codeBlocks.length || current.textLines.length) {
        sections.push({ ...current });
      }

      current = {
        heading: node.textContent.trim(),
        level: parseInt(tag[1]),
        codeBlocks: [],
        textLines: []
      };
    } else if (tag === 'pre' || tag === 'code') {
      const code =
        tag === 'code'
          ? node.textContent
          : node.querySelector('code')?.textContent || node.textContent;

      const lang = node.className?.match(/language-(\w+)/)?.[1] || '';

      current.codeBlocks.push({
        lang,
        code: code.trim()
      });
    } else if (
      node.childNodes.length === 1 &&
      node.childNodes[0].nodeType === Node.TEXT_NODE
    ) {
      const txt = node.textContent.trim();
      if (txt) current.textLines.push(txt);
    }
  }

  if (current.codeBlocks.length || current.textLines.length) {
    sections.push(current);
  }

  return sections;
}

/* ========================= AGGREGATION ========================= */
function aggregateSections(sections) {
  const rows = [];

  for (const sec of sections) {
    const code = sec.codeBlocks.map(b => b.code).join('\n');
    if (!code.trim()) continue;

    rows.push({
      heading: sec.heading,
      code
    });
  }

  const includePatterns = AC_RULES.auth_context?.include_patterns || [];

  if (!includePatterns.length) return rows;

  return rows.filter(r => {
    const txt = `${r.heading} ${r.code}`.toLowerCase();
    return includePatterns.some(p => new RegExp(p, 'i').test(txt));
  });
}

/* ========================= AC ANALYSIS ========================= */
function normalizeReferences(references) {
  if (!references) return [];

  const refs = [];

  function addRef(label, url) {
    if (!url || typeof url !== 'string') return;

    for (const part of url.split('|')) {
      const cleanUrl = part.trim();

      if (cleanUrl.startsWith('http')) {
        refs.push({
          label: label || getReferenceLabel(cleanUrl),
          url: cleanUrl
        });
      }
    }
  }

  if (typeof references === 'string') {
    addRef('', references);
  } else if (Array.isArray(references)) {
    for (const ref of references) {
      if (typeof ref === 'string') {
        addRef('', ref);
      } else if (ref && typeof ref === 'object') {
        if (ref.url) {
          addRef(ref.label, ref.url);
        } else {
          for (const [label, url] of Object.entries(ref)) {
            addRef(label, url);
          }
        }
      }
    }
  } else if (typeof references === 'object') {
    if (references.url) {
      addRef(references.label, references.url);
    } else {
      for (const [label, url] of Object.entries(references)) {
        addRef(label, url);
      }
    }
  }

  const seen = new Set();

  return refs.filter(ref => {
    if (seen.has(ref.url)) return false;
    seen.add(ref.url);
    return true;
  });
}

function renderReferences(references) {
  const links = normalizeReferences(references);

  if (!links.length) return '';

  return `
    <div class="references-list">
      <strong>References:</strong>
      <ul>
        ${links.map(ref => `
          <li>
            <a href="${escapeHtml(ref.url)}" target="_blank" rel="noopener noreferrer">
              ${escapeHtml(getReferenceLabel(ref.url, ref.label))}
            </a>
          </li>
        `).join('')}
      </ul>
    </div>
  `;
}

function getReferenceLabel(url, fallbackLabel = '') {
  const labelMap = {
    cwe: 'MITRE CWE',
    owasp: 'OWASP Broken Access Control',
    spring: 'Spring Security Documentation',
    django: 'Django Documentation'
  };

  if (fallbackLabel && labelMap[fallbackLabel]) return labelMap[fallbackLabel];

  if (url.includes('cwe.mitre.org')) {
    const match = url.match(/definitions\/(\d+)\.html/);
    return match ? `MITRE CWE-${match[1]}` : 'MITRE CWE';
  }

  if (url.includes('docs.spring.io')) return 'Spring Security Documentation';
  if (url.includes('owasp.org')) return 'OWASP Broken Access Control';
  if (url.includes('docs.djangoproject.com')) return 'Django Documentation';

  return fallbackLabel || url;
}

function extractLabeledItems(items, text) {
  const labels = [];
  const evidence = [];

  for (const item of items) {
    if (item.requires) {
      const matched = item.requires.every(req => anyMatch([req], text));

      if (matched) {
        labels.push(item.label);
        evidence.push(...item.requires);
      }
    } else {
      const ev = findMatches(item.patterns || [], text);

      if (ev.length) {
        labels.push(item.label);
        evidence.push(...ev);
      }
    }
  }

  return [
    labels.length ? [...new Set(labels)].sort().join(', ') : 'Undefined/Implicit',
    evidence.length ? [...new Set(evidence)].map(String).sort().join(' | ') : 'None'
  ];
}

function detectAuthFamily(familyRules, text) {
  const labels = [];
  const evidence = [];

  for (const item of familyRules) {
    const ev = findMatches(item.patterns || [], text);

    if (ev.length) {
      labels.push(item.label);
      evidence.push(...ev);
    }
  }

  return labels.length
    ? ['Yes', [...new Set(labels.concat(evidence))].sort().join(' | ')]
    : ['No', 'None'];
}

function dedupeReferences(refs) {
  const seen = new Set();

  return refs.filter(ref => {
    if (!ref.url || seen.has(ref.url)) return false;
    seen.add(ref.url);
    return true;
  });
}

function inferBAC(row, rules) {
  const text = row.code;

  const familyStatus = {
    rbac: row.rbac === 'Yes',
    abac_ownership: row.abac === 'Yes',
    workflow_context: row.contextual === 'Yes'
  };

  const findings = [];
  const cwes = [];
  const severities = [];
  const refs = [];

  for (const rule of rules.bac_inference_rules || []) {
    const ctxPatterns = rule.context_patterns || [];
    const missing = rule.required_missing || [];

    if (ctxPatterns.length && !ctxPatterns.every(p => anyMatch([p], text))) continue;
    if (missing.some(fam => familyStatus[fam])) continue;

    findings.push(`${rule.bac_class}: ${rule.name}`);
    cwes.push(...(rule.cwe_ids || []));
    severities.push(rule.severity || 'review');

    for (const [label, url] of Object.entries(rule.references || {})) {
      refs.push({
        label,
        url
      });
    }
  }

  if (findings.length) {
    return [
      findings.join(' | '),
      [...new Set(cwes)].sort().join(', '),
      [...new Set(severities)].sort().join(', '),
      dedupeReferences(refs)
    ];
  }

  if (row.rbac === 'Yes' || row.abac === 'Yes') {
    return ['Secure/Proper Access Control Signal Present', '', 'info', []];
  }

  return ['No Specific BAC Detected (Review Manually)', '', 'low', []];
}

function analyzeAC(rows) {
  const matrix = AC_RULES.matrix || {};
  const authPatterns = AC_RULES.authorization_patterns || {};
  const out = [];

  for (const row of rows) {
    const code = row.code;

    const [subject] = extractLabeledItems(matrix.subjects || [], code);
    const [object] = extractLabeledItems(matrix.objects || [], code);
    const [operation] = extractLabeledItems(matrix.operations || [], code);

    const [rbacYN, rbacPat] = detectAuthFamily(authPatterns.rbac || [], code);
    const [abacYN, abacPat] = detectAuthFamily(authPatterns.abac_ownership || [], code);
    const [ctxYN, ctxPat] = detectAuthFamily(authPatterns.workflow_context || [], code);

    const r = {
      ...row,
      subject,
      object,
      operation,
      rbac: rbacYN,
      abac: abacYN,
      contextual: ctxYN
    };

    const [bacType, bacCWE, bacSev, bacRef] = inferBAC(r, AC_RULES);

    out.push({
      ...r,
      rbacPat,
      abacPat,
      ctxPat,
      bacType,
      bacCWE,
      bacSev,
      bacRef
    });
  }

  return out;
}

/* ========================= CWE ANALYSIS ========================= */
function scanCWE(code, rulesDoc) {
  const findings = [];
  const matchingCfg = rulesDoc.matching || {};
  const windowLines = parseInt(matchingCfg.window_lines || 6);
  const seen = new Set();

  for (const rule of rulesDoc.rules || []) {
    const patterns = rule.patterns || [];
    const antiPatterns = rule.anti_patterns || [];

    for (const pattern of patterns) {
      const r = compilePattern(pattern);
      if (!r) continue;

      let m;

      while ((m = r.exec(code)) !== null) {
        const [window, startLine, endLine] = boundedWindow(
          code,
          m.index,
          m.index + m[0].length,
          windowLines
        );

        if (antiPatterns.length && hasAntipattern(antiPatterns, window)) continue;

        const key = `${rule.cwe_id}||${pattern}||${startLine}||${endLine}`;
        if (seen.has(key)) continue;

        seen.add(key);

        findings.push({
          cwe_id: rule.cwe_id || rule.id || '',
          cwe_name: rule.name || '',
          ruleset: rule.ruleset || rulesDoc.ruleset || '',
          category: rule.category || '',
          severity: rule.severity || '',
          confidence: rule.confidence || 'heuristic',
          why: rule.why || '',
          matched_pattern: pattern,
          matched_text: m[0].replace(/\s+/g, ' ').trim().slice(0, 240),
          match_line: lineNumber(code, m.index),
          window_start_line: startLine,
          window_end_line: endLine,
          match_snippet: window.slice(0, 1200),
          references: rule.references || [],
          notes: (rule.notes || []).join(' | ')
        });

        if (m.index === r.lastIndex) r.lastIndex++;
      }
    }
  }

  return findings;
}

function analyzeCWE(rows) {
  const out = [];

  for (const row of rows) {
    const findings = scanCWE(row.code, CWE_RULES);
    out.push({
      ...row,
      findings
    });
  }

  return out;
}

/* ========================= RENDERING ========================= */
function severityClass(sev) {
  const s = (sev || '').toLowerCase();

  if (s.includes('critical')) return 'critical';
  if (s.includes('high')) return 'high';
  if (s.includes('medium')) return 'medium';
  if (s.includes('low')) return 'low';

  return 'info';
}

function renderResults(acRows, cweRows) {
  const container = document.getElementById('resultsBody');

  if (!acRows.length) {
    container.innerHTML = '<div class="empty-state">No auth-related code blocks found.</div>';
    document.getElementById('resultCount').textContent = '';
    return;
  }

  let html = '';
  let totalFindings = 0;

  for (let i = 0; i < acRows.length; i++) {
    const ac = acRows[i];
    const cwe = cweRows[i];
    const findings = cwe.findings || [];

    totalFindings += findings.length;

    const hasIssue =
      findings.length > 0 ||
      (ac.bacType && !ac.bacType.includes('Secure') && !ac.bacType.includes('N/A'));

    const badgeClass = hasIssue
      ? findings.some(f => f.severity === 'critical')
        ? 'critical'
        : findings.some(f => f.severity === 'high')
          ? 'high'
          : 'medium'
      : 'success';

    const badgeText = hasIssue
      ? `${findings.length} CWE` +
        (ac.bacType && !ac.bacType.includes('Secure') ? ' + BAC' : '')
      : 'Clean';

    html += `
      <div class="section">
        <div class="section-header" onclick="this.classList.toggle('active');this.nextElementSibling.classList.toggle('open')">
          <span>${escapeHtml(ac.heading)}</span>
          <div class="meta">
            <span class="tag ${badgeClass}">${badgeText}</span>
          </div>
        </div>

        <div class="section-body">
          <div style="margin-bottom:14px;">
            <strong>Access Control Matrix</strong>

            <div class="matrix-grid">
              <div class="matrix-label">Subject</div>
              <div class="matrix-value">${escapeHtml(ac.subject)}</div>

              <div class="matrix-label">Object</div>
              <div class="matrix-value">${escapeHtml(ac.object)}</div>

              <div class="matrix-label">Operation</div>
              <div class="matrix-value">${escapeHtml(ac.operation)}</div>
            </div>

            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
              <span class="tag ${ac.rbac === 'Yes' ? 'success' : 'low'}">RBAC: ${ac.rbac}</span>
              <span class="tag ${ac.abac === 'Yes' ? 'success' : 'low'}">ABAC: ${ac.abac}</span>
              <span class="tag ${ac.contextual === 'Yes' ? 'success' : 'low'}">Contextual: ${ac.contextual}</span>
            </div>

            ${
              ac.bacType &&
              !ac.bacType.includes('Secure') &&
              !ac.bacType.includes('N/A') &&
              !ac.bacType.includes('No Specific')
                ? `
                  <div class="finding ${severityClass(ac.bacSev)}" style="margin-top:10px;">
                    <div class="finding-title">BAC Inference: ${escapeHtml(ac.bacType)}</div>
                    <div class="finding-meta">
                      CWE: ${escapeHtml(ac.bacCWE || '—')}
                      &middot;
                      Severity: ${escapeHtml(ac.bacSev || '—')}
                    </div>
                    ${renderReferences(ac.bacRef)}
                  </div>
                `
                : ac.bacType
                  ? `
                    <div style="margin-top:8px;font-size:12px;color:var(--success);font-weight:500;">
                      ${escapeHtml(ac.bacType)}
                    </div>
                  `
                  : ''
            }
          </div>

          ${
            findings.length
              ? `<div style="margin-bottom:14px;"><strong>CWE Findings (${findings.length})</strong>`
              : `
                <div style="margin-bottom:14px;">
                  <strong>CWE Findings</strong>
                  <div style="font-size:12px;color:var(--text-secondary);margin-top:4px;">
                    No vulnerability patterns matched.
                  </div>
              `
          }

          ${findings.map(f => `
            <div class="finding ${severityClass(f.severity)}">
              <div class="finding-title">
                ${escapeHtml(f.cwe_id)} — ${escapeHtml(f.cwe_name)}
              </div>

              <div class="finding-meta">
                ${escapeHtml(f.why)}
              </div>

              <div class="finding-meta">
                Matched:
                <code>${escapeHtml(f.matched_text)}</code>
                (line ${f.match_line})
              </div>

              <div class="finding-meta">
                Severity: ${escapeHtml(f.severity)}
                · Confidence: ${escapeHtml(f.confidence)}
                · Ruleset: ${escapeHtml(f.ruleset)}
              </div>

              ${renderReferences(f.references)}

              ${
                f.notes
                  ? `
                    <div class="finding-meta" style="margin-top:4px;color:var(--text-secondary);">
                      Note: ${escapeHtml(f.notes)}
                    </div>
                  `
                  : ''
              }

              ${renderCodeWithLineNumbers(f.match_snippet, f.window_start_line || 1)}
            </div>
          `).join('')}

          </div>

          <details style="margin-top:10px;">
            <summary style="font-size:12px;color:var(--text-secondary);cursor:pointer;">
              View source code
            </summary>
            ${renderCodeWithLineNumbers(ac.code)}
          </details>
        </div>
      </div>
    `;
  }

  container.innerHTML = html;
  document.getElementById('resultCount').textContent =
    `${acRows.length} sections · ${totalFindings} findings`;
}

/* ========================= MAIN FLOW ========================= */
function runAnalysis() {
  const raw = document.getElementById('rawInput').value;
  if (!raw.trim()) return;

  const isHTML = raw.trim().startsWith('<');
  const sections = isHTML ? parseHTML(raw) : parseMarkdown(raw);
  const rows = aggregateSections(sections);
  const acRows = analyzeAC(rows);
  const cweRows = analyzeCWE(rows);

  renderResults(acRows, cweRows);
}

function clearAll() {
  document.getElementById('rawInput').value = '';
  document.getElementById('resultsBody').innerHTML =
    '<div class="empty-state">Upload or paste content, then click Analyze.</div>';
  document.getElementById('resultCount').textContent = '';
}

function loadSample() {
  document.getElementById('rawInput').value = `## Login View
\`\`\`python
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect

def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect(request.GET.get('next', '/dashboard'))
    return render(request, 'login.html')
\`\`\`

## Dashboard View
\`\`\`python
from django.shortcuts import render
from django.contrib.auth.models import User

def dashboard(request):
    users = User.objects.all()
    return render(request, 'dashboard.html', {'users': users})
\`\`\`

## Admin Panel
\`\`\`python
from django.shortcuts import render

def admin_panel(request):
    return render(request, 'admin.html')
\`\`\`

## Profile Update
\`\`\`python
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User

def update_profile(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    if request.method == 'POST':
        user.email = request.POST['email']
        user.save()
    return render(request, 'profile.html', {'user': user})
\`\`\`
`;
}

/* ========================= FILE HANDLING ========================= */
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const sampleBtn = document.getElementById('sampleBtn');
const clearBtn = document.getElementById('clearBtn');

window.runAnalysis = runAnalysis;
window.loadSample = loadSample;
window.clearAll = clearAll;

if (analyzeBtn) analyzeBtn.addEventListener('click', runAnalysis);
if (sampleBtn) sampleBtn.addEventListener('click', loadSample);
if (clearBtn) clearBtn.addEventListener('click', clearAll);

if (dropzone && fileInput) {
  dropzone.addEventListener('click', () => fileInput.click());

  dropzone.addEventListener('dragover', e => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });

  dropzone.addEventListener('drop', e => {
    e.preventDefault();
    dropzone.classList.remove('dragover');

    if (e.dataTransfer.files.length) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', e => {
    if (e.target.files.length) {
      handleFile(e.target.files[0]);
    }
  });
}

function handleFile(file) {
  const reader = new FileReader();

  reader.onload = e => {
    document.getElementById('rawInput').value = e.target.result;
  };

  reader.readAsText(file);
}