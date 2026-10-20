(() => {
  "use strict";
  const { nodes, edges } = window.GRAPH_DATA,
    canvas = document.getElementById("graphCanvas"),
    ctx = canvas.getContext("2d");
  const $ = (id) => document.getElementById(id);
  const positions = nodes.map((n) => ({ x: Number(n[3]), y: Number(n[4]) }));
  let zoom = 1,
    panX = 0,
    panY = 0,
    width = 0,
    height = 0,
    selected = -1,
    minimum = 1,
    drag = null,
    scheduled = false;
  const maxWeight = Math.max(1, ...edges.map((e) => e[2]));
  $("weightFilter").max = maxWeight;
  function node(tag, text, className) {
    const el = document.createElement(tag);
    if (text !== undefined) el.textContent = text;
    if (className) el.className = className;
    return el;
  }
  function safeURL(value) {
    try {
      const url = new URL(value);
      return ["https:", "http:"].includes(url.protocol) ? url.href : null;
    } catch {
      return null;
    }
  }
  function visibleEdges() {
    return edges.filter((e) => e[2] >= minimum);
  }
  function schedule() {
    if (!scheduled) {
      scheduled = true;
      requestAnimationFrame(() => {
        scheduled = false;
        draw();
      });
    }
  }
  function resize() {
    const r = canvas.getBoundingClientRect();
    width = r.width;
    height = r.height;
    const ratio = Math.min(2, devicePixelRatio || 1);
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    schedule();
  }
  function fit() {
    const xs = positions.map((p) => p.x),
      ys = positions.map((p) => p.y),
      minX = Math.min(...xs),
      maxX = Math.max(...xs),
      minY = Math.min(...ys),
      maxY = Math.max(...ys);
    zoom = Math.max(
      0.01,
      Math.min(
        (width - 90) / Math.max(1, maxX - minX),
        (height - 80) / Math.max(1, maxY - minY),
      ),
    );
    panX = (width - (maxX - minX) * zoom) / 2 - minX * zoom;
    panY = (height - (maxY - minY) * zoom) / 2 - minY * zoom - 12;
    schedule();
  }
  function draw() {
    const s = getComputedStyle(document.documentElement),
      color = (n) => s.getPropertyValue(n).trim();
    ctx.clearRect(0, 0, width, height);
    const visible = visibleEdges(),
      neighbors = new Set();
    if (selected >= 0) {
      neighbors.add(selected);
      for (const e of visible)
        if (e[0] === selected || e[1] === selected) {
          neighbors.add(e[0]);
          neighbors.add(e[1]);
        }
    }
    const point = (i) => ({
      x: positions[i].x * zoom + panX,
      y: positions[i].y * zoom + panY,
    });
    for (const edge of visible) {
      const from = point(edge[0]),
        to = point(edge[1]),
        highlight =
          selected >= 0 && (edge[0] === selected || edge[1] === selected);
      ctx.globalAlpha = selected < 0 ? 0.22 : highlight ? 0.85 : 0.045;
      ctx.strokeStyle = edge[4]
        ? color("--danger")
        : highlight
          ? color("--accent")
          : color("--muted");
      ctx.lineWidth = highlight ? 2 : Math.min(3, 1 + Math.log1p(edge[2]) / 3);
      ctx.beginPath();
      ctx.moveTo(from.x, from.y);
      ctx.lineTo(to.x, to.y);
      ctx.stroke();
    }
    ctx.font = "11px system-ui";
    for (let i = 0; i < nodes.length; i++) {
      const p = point(i);
      if (p.x < -20 || p.x > width + 20 || p.y < -20 || p.y > height + 20)
        continue;
      ctx.globalAlpha = selected < 0 || neighbors.has(i) ? 1 : 0.15;
      ctx.fillStyle = [color("--accent"), color("--link"), color("--warning")][
        Math.min(2, Math.max(0, nodes[i][2]))
      ];
      ctx.beginPath();
      ctx.arc(
        p.x,
        p.y,
        i === selected ? 7 : Math.max(2, Math.min(5, zoom * 5)),
        0,
        Math.PI * 2,
      );
      ctx.fill();
      if (i === selected || zoom > 1.7) {
        ctx.fillStyle = color("--text");
        ctx.fillText(nodes[i][1].slice(0, 55), p.x + 9, p.y + 4);
      }
    }
    ctx.globalAlpha = 1;
    $("graphSummary").textContent =
      `${nodes.length} tutorials · ${visible.length} of ${edges.length} connections · Three dependency levels`;
  }
  function zoomBy(factor, cx = width / 2, cy = height / 2) {
    const next = Math.min(30, Math.max(0.01, zoom * factor)),
      ratio = next / zoom;
    panX = cx - (cx - panX) * ratio;
    panY = cy - (cy - panY) * ratio;
    zoom = next;
    schedule();
  }
  function results() {
    const query = $("nodeSearch").value.trim().toLowerCase();
    const matches = nodes
      .map((n, i) => ({ n, i }))
      .filter(({ n }) => (n[0] + " " + n[1]).toLowerCase().includes(query));
    $("resultCount").textContent =
      `${matches.length} matching tutorials${matches.length > 30 ? " · First 30 shown" : ""}`;
    $("nodeResults").replaceChildren(
      ...matches.slice(0, 30).map(({ n, i }) => {
        const b = node("button", n[1]);
        b.type = "button";
        b.setAttribute("aria-pressed", String(selected === i));
        b.addEventListener("click", () => choose(i, true));
        return b;
      }),
    );
  }
  function choose(index, focus = false) {
    selected = index;
    if (focus) {
      zoom = Math.max(zoom, 0.65);
      panX = width / 2 - positions[index].x * zoom;
      panY = height / 2 - positions[index].y * zoom;
    }
    details();
    results();
    schedule();
  }
  function details() {
    const target = $("nodeDetails");
    if (selected < 0) {
      target.replaceChildren(
        node("p", "Select a tutorial to see its connections."),
      );
      return;
    }
    const item = nodes[selected],
      connections = visibleEdges().filter(
        (e) => e[0] === selected || e[1] === selected,
      );
    const heading = node("h2", item[1]),
      link = node("a", "Open tutorial ↗");
    const href = safeURL(item[0]);
    if (href) {
      link.href = href;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
    } else link.textContent = "URL unavailable";
    const info = node(
      "p",
      `Depth ${item[2]} · ${connections.filter((e) => e[1] === selected).length} incoming · ${connections.filter((e) => e[0] === selected).length} outgoing visible connections`,
    );
    const list = node("ul");
    for (const edge of connections.slice(0, 20)) {
      const other = edge[0] === selected ? edge[1] : edge[0],
        li = node("li"),
        b = node("button", nodes[other][1] + " · " + edge[2]);
      b.type = "button";
      b.addEventListener("click", () => choose(other));
      li.append(b);
      list.append(li);
    }
    const keywords = new Set(connections.flatMap((e) => e[3]));
    target.replaceChildren(
      heading,
      link,
      info,
      node("h3", "Connected tutorials"),
      list,
      node("h3", "Keywords"),
      ...Array.from(keywords)
        .slice(0, 30)
        .map((k) => node("span", k, "keyword")),
    );
  }
  canvas.addEventListener("pointerdown", (e) => {
    canvas.setPointerCapture(e.pointerId);
    drag = { x: e.clientX, y: e.clientY, startX: e.clientX, startY: e.clientY };
  });
  canvas.addEventListener("pointermove", (e) => {
    if (!drag) return;
    panX += e.clientX - drag.x;
    panY += e.clientY - drag.y;
    drag.x = e.clientX;
    drag.y = e.clientY;
    schedule();
  });
  canvas.addEventListener("pointerup", (e) => {
    if (!drag) return;
    const click =
      Math.hypot(e.clientX - drag.startX, e.clientY - drag.startY) < 5;
    drag = null;
    if (!click) return;
    const r = canvas.getBoundingClientRect(),
      x = e.clientX - r.left,
      y = e.clientY - r.top;
    let closest = -1,
      distance = 14;
    positions.forEach((p, i) => {
      const d = Math.hypot(p.x * zoom + panX - x, p.y * zoom + panY - y);
      if (d < distance) {
        distance = d;
        closest = i;
      }
    });
    if (closest >= 0) choose(closest);
  });
  canvas.addEventListener("pointercancel", () => {
    drag = null;
  });
  canvas.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      const r = canvas.getBoundingClientRect();
      zoomBy(
        Math.exp(-e.deltaY * 0.001),
        e.clientX - r.left,
        e.clientY - r.top,
      );
    },
    { passive: false },
  );
  $("zoomIn").addEventListener("click", () => zoomBy(1.35));
  $("zoomOut").addEventListener("click", () => zoomBy(1 / 1.35));
  $("fitGraph").addEventListener("click", fit);
  $("resetGraph").addEventListener("click", () => {
    selected = -1;
    minimum = 1;
    $("weightFilter").value = 1;
    $("weightValue").value = "1";
    $("nodeSearch").value = "";
    details();
    results();
    fit();
  });
  $("weightFilter").addEventListener("input", (e) => {
    minimum = Number(e.target.value);
    $("weightValue").value = String(minimum);
    details();
    schedule();
  });
  $("nodeSearch").addEventListener("input", results);
  window.addEventListener("themechange", schedule);
  new ResizeObserver(() => {
    resize();
  }).observe(canvas);
  resize();
  fit();
  results();
})();
