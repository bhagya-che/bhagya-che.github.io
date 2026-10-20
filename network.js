(() => {
  "use strict";
  const { elements, summary, top_keywords: topKeywords } = window.NETWORK_DATA;
  const color = (name) =>
    getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const escapeHTML = (value) =>
    String(value).replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  // ---------- If positions are missing, build 3-column preset ----------
  (function ensureThreeColumnPositions() {
    // Detect if nodes have positions
    const hasPos = elements.some(
      (el) =>
        el.position &&
        Number.isFinite(el.position.x) &&
        Number.isFinite(el.position.y),
    );
    if (hasPos) return;

    // Build layer lists by depth
    const L0 = [],
      L1 = [],
      L2 = [];
    elements.forEach((el) => {
      if (el.group === "nodes" || el.data?.id) {
        const d =
          el.data && typeof el.data.depth === "number" ? el.data.depth : 1;
        if (d === 0) L0.push(el);
        else if (d === 1) L1.push(el);
        else L2.push(el);
      }
    });

    // Horizontal positions (more separation)
    const x_L0 = 0,
      x_L1 = 700,
      x_L2 = 1500;

    // Vertical spacing with extra room for depth-2
    function spacedY(n, base = 900, gap = 1.0) {
      if (n <= 1) return [base / 2];
      const step = (base * gap) / (n + 1);
      return Array.from({ length: n }, (_, i) => step * (i + 1));
    }
    const y0 = spacedY(L0.length, 900, 1.0);
    const y1 = spacedY(L1.length, 900, 1.2);
    const y2 = spacedY(L2.length, 900, Math.min(3.0, 1.0 + L2.length / 100)); // auto-expand if many leaves

    L0.forEach((el, i) => {
      el.position = { x: x_L0, y: y0[i] };
    });
    L1.forEach((el, i) => {
      el.position = { x: x_L1, y: y1[i] };
    });
    L2.forEach((el, i) => {
      el.position = { x: x_L2, y: y2[i] };
    });
  })();

  // ---------- UI: overall + keywords ----------
  document.getElementById("overall").innerHTML =
    '<span class="pill">Nodes: ' +
    summary.total_nodes +
    "</span>" +
    '<span class="pill">Edges: ' +
    summary.total_edges +
    "</span>" +
    '<span class="pill">Cycles: ' +
    summary.cycles +
    "</span>";

  const topKwDiv = document.getElementById("topkw");
  topKeywords.forEach((row) => {
    const span = document.createElement("span");
    span.className = "kw";
    span.textContent = row.keyword + " (" + row.count + ")";
    topKwDiv.appendChild(span);
  });

  // ---------- Compute global weight range ----------
  const weights = elements
    .filter((el) => el.data && typeof el.data.weight === "number")
    .map((el) => el.data.weight);
  const wmin = weights.length ? Math.min(...weights) : 0;
  const wmax = weights.length ? Math.max(...weights) : 1;

  function edgeWidth(w) {
    if (wmax <= wmin) return 3;
    return 1 + Math.round((7 * (w - wmin)) / (wmax - wmin));
  }

  // ---------- Build Cytoscape ----------
  const cy = cytoscape({
    container: document.getElementById("cy"),
    elements: elements,
    layout: { name: "preset" }, // we provide positions
    wheelSensitivity: 0.2, // smoother zoom
    minZoom: 0.05,
    maxZoom: 5,
    style: [
      {
        selector: "node",
        style: {
          shape: "ellipse",
          width: 16,
          height: 16,
          "background-color": (ele) => {
            const d = ele.data("depth");
            if (d === 0) return "#2563eb"; // depth0
            if (d === 1) return "#60a5fa"; // depth1
            return "#bfdbfe"; // depth2
          },
          label: "data(label)",
          "font-size": 9,
          "text-valign": "top",
          "text-halign": "center",
          "text-margin-y": -10,
          color: color("--text-primary"),
        },
      },
      {
        selector: "edge",
        style: {
          "curve-style": "bezier",
          opacity: 0.22,
          "line-color": (ele) => (ele.data("cycle") ? "#d61f1f" : "#9ca3af"),
          width: (ele) => edgeWidth(ele.data("weight") || 1),
          "target-arrow-shape": "triangle",
          "target-arrow-color": (ele) =>
            ele.data("cycle") ? "#d61f1f" : "#9ca3af",
        },
      },
      { selector: ".faded", style: { opacity: 0.07 } },
      {
        selector: ".highlight",
        style: {
          opacity: 0.95,
          "line-color": (ele) => (ele.data("cycle") ? "#b91c1c" : "#374151"),
          "target-arrow-color": (ele) =>
            ele.data("cycle") ? "#b91c1c" : "#374151",
          width: (ele) => Math.max(edgeWidth(ele.data("weight") || 1), 3),
        },
      },
    ],
  });

  // ---------- Controls ----------
  const slider = document.getElementById("wslider");
  const wval = document.getElementById("wval");
  function applyWeightFilter(minW) {
    wval.textContent = String(minW);
    cy.edges().forEach((e) => {
      const show = (e.data("weight") || 0) >= minW;
      e.style("display", show ? "element" : "none");
    });
  }
  slider.max = String(wmax);
  slider.value = "0";
  applyWeightFilter(0);
  slider.addEventListener("input", (e) =>
    applyWeightFilter(parseInt(e.target.value || "0", 10)),
  );

  document.getElementById("fitBtn").addEventListener("click", () => {
    cy.fit(cy.elements(), 40);
  });

  document.getElementById("resetBtn").addEventListener("click", () => {
    cy.elements().removeClass("faded").removeClass("highlight");
    document.getElementById("selTitle").textContent =
      "Click a node to inspect its neighborhood.";
    document.getElementById("selTitle").className = "stat muted";
    document.getElementById("selStats").replaceChildren();
    slider.value = "0";
    applyWeightFilter(0);
    cy.fit(cy.elements(), 40);
  });

  // ---------- Click: focus neighborhood + stats ----------
  cy.on("tap", "node", function (evt) {
    const node = evt.target;
    const nbhd = node.closedNeighborhood(); // node + incident edges + neighbors

    cy.elements().addClass("faded").removeClass("highlight");
    nbhd.removeClass("faded").addClass("highlight");

    const title = document.getElementById("selTitle");
    title.textContent = node.data("full") || node.id();
    title.className = "stat";

    const inEdges = node.incomers("edge").filter(":visible");
    const outEdges = node.outgoers("edge").filter(":visible");
    const allEdges = inEdges.union(outEdges);

    let wsum = 0,
      wcnt = 0;
    const kwCounts = new Map();
    const neighborCounts = new Map();

    allEdges.forEach((e) => {
      const w = e.data("weight") || 0;
      wsum += w;
      wcnt += 1;

      const kws = e.data("keywords") || [];
      kws.forEach((k) => kwCounts.set(k, (kwCounts.get(k) || 0) + 1));

      const s = e.data("source"),
        t = e.data("target");
      const other = s === node.id() ? t : s;
      neighborCounts.set(other, (neighborCounts.get(other) || 0) + 1);
    });

    const topK = Array.from(kwCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
    const topN = Array.from(neighborCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    const statsDiv = document.getElementById("selStats");
    statsDiv.innerHTML = `
        <div class="stat"><span class="pill">In edges: ${inEdges.length}</span>
                          <span class="pill">Out edges: ${outEdges.length}</span>
                          <span class="pill">Visible edges: ${allEdges.length}</span></div>
        <div class="stat"><span class="pill">Sum weight: ${wsum}</span>
                          <span class="pill">Avg weight: ${wcnt ? (wsum / wcnt).toFixed(2) : "0.00"}</span></div>
        <div class="section-title">Top Neighbors</div>
        <div>${topN.map(([id, c]) => '<div class="stat">' + escapeHTML(id) + ' <span class="pill">' + c + "</span></div>").join("")}</div>
        <div class="section-title">Top Keywords</div>
        <div>${topK.map(([k, c]) => '<span class="kw">' + escapeHTML(k) + " (" + c + ")</span>").join("")}</div>
      `;
  });

  // Initial fit to make everything visible; users can pan/zoom or just scroll sidebar
  cy.fit(cy.elements(), 40);

  function applyTheme() {
    cy.style()
      .selector("node")
      .style("color", color("--text-primary"))
      .selector("edge")
      .style({
        "line-color": (e) =>
          e.data("cycle") ? color("--terminal-red") : color("--text-secondary"),
        "target-arrow-color": (e) =>
          e.data("cycle") ? color("--terminal-red") : color("--text-secondary"),
      })
      .selector(".highlight")
      .style({
        "line-color": (e) =>
          e.data("cycle") ? color("--terminal-red") : color("--terminal-blue"),
        "target-arrow-color": (e) =>
          e.data("cycle") ? color("--terminal-red") : color("--terminal-blue"),
      })
      .update();
  }
  window.addEventListener("themechange", applyTheme);
  applyTheme();
})();
