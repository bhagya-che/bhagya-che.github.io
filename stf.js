"use strict";

// Slides: invitation + technical primer on SSTI and supporting knowledge (no exploit payloads)
const slides = [
  {
    title: "What is a vulnerability?",
    content: `<p>A vulnerability is a <b>weakness or flaw</b> in a computer system or program that could let someone cause problems. </p>
              <ul>
                <li>Example: a door with a broken lock  anyone could walk in.</li>
                <li>In computers: a program with a missing check could let attackers steal or change data.</li>
                <li>A vulnerability is just the weak spot. An <i>attack</i> happens when someone takes advantage of it.</li>
              </ul>`,
  },

  {
    title: "What is injection?",
    content: `<p>Injection happens when <b>untrusted input</b> is mixed into code or commands in a way the program did not expect.</p>
              <ul>
                <li>Example: If you ask a calculator for "2+2" that’s fine, but if you sneak in "delete everything" and it runs that, it’s a problem.</li>
                <li>In web apps, injection means user input changes how the server behaves  instead of just being stored or shown.</li>
                <li>Different types: SQL Injection, Command Injection, Template Injection, etc.</li>
              </ul>`,
  },

  {
    title: "Welcome to STL CTF 2025",
    content: `<p>Welcome! This session will give you the basic ideas you need to explore a simple web app safely. No prior web or security experience required  we'll build step by step.</p>`,
  },

  {
    title: "What you'll learn",
    content: `<ul>
                <li>What template engines are and where they run (server vs client).</li>
                <li>How to test whether a web page is evaluating (running) your input or just showing it back.</li>
                <li>How to run safe, harmless tests that don't break anything.</li>
                <li>How these ideas connect to common security lists like OWASP/CWE at a high level.</li>
              </ul>`,
  },

  {
    title: "Very quick HTTP refresher",
    content: `<ul>
                <li>A request is what your browser sends: it has a method (GET/POST), a path (which page), headers, and sometimes a body.</li>
                <li>A response is what the server sends back: it has a status (200, 404, etc.), headers, and a body (usually HTML).</li>
                <li>Use the browser Network panel to see what you send and what the server returns  it helps you follow the app's behavior.</li>
              </ul>`,
  },

  {
    title: "What is a template engine?",
    content: `<p>A template engine is a tool the server uses to create web pages. Think of a template like a blank form with placeholders; the server fills those placeholders with data to make the final HTML that your browser shows.</p>
              <p>Important: templates can also run small pieces of code (expressions). If user input ends up being treated as code, the template might run it.</p>`,
  },

  {
    title: "Server-Side Template Injection (SSTI)",
    content: `<ul>
                <li>SSTI happens when user input is accidentally treated as template code by the server.</li>
                <li>That can let someone make the template do things it wasn't meant to, like show hidden data.</li>
                <li>How bad it is depends on the template engine and what the server lets templates access.</li>
              </ul>`,
  },

  {
    title: "Why SSTI matters",
    content: `<ul>
                <li>It can reveal sensitive information (files, config values).</li>
                <li>In some setups, it can let an attacker make the server run commands  that is more serious.</li>
                <li>Even small leaks help an attacker learn more about the app, which can lead to bigger problems.</li>
              </ul>`,
  },

  {
    title: "Safe testing principles",
    content: `<ul>
                <li>Start with harmless tests  e.g., simple math expressions that show whether something was evaluated.</li>
                <li>Do NOT run destructive commands (like deleting files) on real servers.</li>
                <li>Practice in your own sandbox or CTF environment where you're allowed to test.</li>
              </ul>`,
  },

  {
    title: "Template engines to know",
    content: `<ul>
                <li><b>Jinja2</b>  often used with Python/Flask.</li>
                <li><b>Twig</b>  common with PHP frameworks. <b>ERB</b>  Ruby. <b>Handlebars</b>  JS.</li>
                <li>Each engine has its own syntax and available functions  spotting the engine helps you pick the right tests.</li>
              </ul>`,
  },

  {
    title: "How to spot templates being used",
    content: `<ul>
                <li>Look where the site shows back what you typed. Is it shown exactly, or transformed/evaluated?</li>
                <li>Error messages or odd output sometimes reveal the framework or template engine.</li>
                <li>Check the page source and network responses for hints (comments, headers, or stack traces).</li>
              </ul>`,
  },

  {
    title: "DevTools & quick checks",
    content: `<ul>
                <li>Network tab: see each request and response.</li>
                <li>Console: try small encodings/decodings (base64, URL) to understand data flow.</li>
                <li>Application/Storage: inspect cookies and local storage to know what the app remembers about you.</li>
              </ul>`,
  },

  {
    title: "A gentle probing method ",
    content:
      `<ol>
                <li><strong>Observe</strong>: find where your input appears in the page.</li>
                <li><strong>Probe</strong>: send harmless tests (like ` +
      "`{{1+1}}`" +
      ` or other engine-appropriate small expressions) to check if the server evaluated them.</li>
                <li><strong>Learn</strong>: when evaluation is confirmed, test which objects or functions are visible  but avoid dangerous actions.</li>
                <li><strong>Demonstrate</strong>: create a minimal, non-destructive proof that something is wrong (for example, showing a hidden config value that is safe to demonstrate).</li>
              </ol>`,
  },

  {
    title: "What developers should do (defensive patterns)",
    content: `<ul>
                <li>Never treat raw user input as template code.</li>
                <li>Escape or sanitize user content based on where it will appear (HTML, JavaScript, CSS).</li>
                <li>Use sandboxed template features or restrict what templates can access if the engine supports it.</li>
              </ul>`,
  },

  {
    title: "Server side best practices",
    content: `<ul>
                <li>Don't put secrets into templates or the template context.</li>
                <li>Log unusual template errors and rate-limit suspicious requests.</li>
                <li>Run the app with minimal permissions so it cannot access more than it needs.</li>
              </ul>`,
  },

  {
    title: "How this maps to OWASP & CWE ",
    content: `<ul>
                <li>Template issues relate to injection problems and to mistakes in how access or data trust is handled.</li>
                <li>Learning these concepts helps you understand categories used by OWASP and CWE  useful for reading reports or guides later.</li>
              </ul>`,
  },

  {
    title: "Tools you'll use",
    content: `<ul>
                <li><b>Browser DevTools</b>  inspect pages and network traffic.</li>
                <li><b>curl / httpie</b>  send crafted requests from the command line.</li>
                <li>Simple decoders and a REPL (Python/Node) to try quick transformations.</li>
              </ul>`,
  },

  {
    title: "Ethics & scope",
    content: `<p>Only test systems where you have permission (CTF targets or personal labs). If you find a problem on a real site, do not exploit it  report it responsibly.</p>`,
  },

  {
    title: "Further reading",
    content: `<ul>
                <li>Start with OWASP pages about Injection and Web Security (for concepts, not payloads).</li>
                <li>Practice on intentionally vulnerable labs or CTF problems.</li>
                <li>Read secure template usage guides for frameworks you use (Flask, Django, PHP, etc.).</li>
              </ul>`,
  },

  {
    title: "Challenge overview (non-spoiler)",
    content: `<p>The CTF challenge is designed to teach you how template engines behave and how small mistakes in server trust can lead to information leaks. Your goal is to apply safe tests to discover a misconfiguration and make a careful, non-destructive proof-of-concept.</p>`,
  },

  {
    title: "Playbook (what to try first)",
    content: `<ol>
                <li>Explore the UI and find inputs that are echoed back.</li>
                <li>Confirm whether input is evaluated using harmless tests.</li>
                <li>See what the template environment exposes without running anything dangerous.</li>
              </ol>`,
  },

  {
    title: "Good luck!",
    content: `<p>You're ready with a basic mental model: what vulnerabilities are, what injection means, how templates work, and how to test safely. Go explore the challenge, learn, and report responsibly. 🎯</p>`,
  },
];

let step = 0;
const titleEl = document.getElementById("slide-title");
const contentEl = document.getElementById("slide-content");
const counterEl = document.getElementById("counter");
const barEl = document.getElementById("progress");
const prevBtn = document.getElementById("prev");
const nextBtn = document.getElementById("next");

function render() {
  const s = slides[step];
  titleEl.textContent = s.title;
  contentEl.innerHTML = s.content;
  counterEl.textContent = `${step + 1} / ${slides.length}`;
  const pct = ((step + 1) / slides.length) * 100;
  barEl.style.width = pct + "%";
  prevBtn.disabled = step === 0;
  nextBtn.textContent = step === slides.length - 1 ? "Finish" : "Next ▶";
}

prevBtn.addEventListener("click", () => {
  if (step > 0) {
    step--;
    render();
  }
});
nextBtn.addEventListener("click", () => {
  if (step < slides.length - 1) {
    step++;
    render();
  }
});

window.addEventListener("keydown", (e) => {
  if (
    /INPUT|TEXTAREA|SELECT/.test(e.target.tagName) ||
    e.target.closest("button,a")
  )
    return;
  if (e.key === "ArrowLeft") {
    if (step > 0) {
      step--;
      render();
    }
  }
  if (e.key === "ArrowRight") {
    if (step < slides.length - 1) {
      step++;
      render();
    }
  }
  if (e.key.toLowerCase() === "p") {
    window.print();
  }
});

render();
