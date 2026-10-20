# Original terminal portfolio — focused update

1. Extract the entire folder.
2. Open `index.html` in your browser.
3. Use the sun/moon button to switch colors, or **Auto** to follow the browser theme. Open **Fitness planner** from the existing Activities & Outreach section.

The original terminal introduction, typing effect, monospace typography, neon dark palette, section layouts, profile image treatment and activity sidebar are retained. The original CTF, BUNFI, presentation, graph and fictional grade-demo interfaces are retained as well. The earlier redesigned portfolio is not included.

## Changes

- Added light/dark themes and accessible sun/moon controls without replacing the template.
- Added the fitness planner alongside the existing activity links. Its personal measurements, demographics, fixed contest dates and targets start blank.
- Moved inline CSS/JavaScript into maintainable local files, removed the unused original stylesheet and duplicate Contact navigation, and removed the redundant cursor timer.
- Kept the original graph interface, fixed data initialization order, and bundled its existing Cytoscape 3.26.0 dependency for offline loading. Its MIT license is in `assets/cytoscape-LICENSE.txt`.
- Kept privacy and security fixes: stripped photo/PDF metadata, guarded local storage, validated fitness imports, safe text rendering, safer CSV exports, restrictive page policies and external-link protection. Work content and email remain public.

## Fitness and local data

**Save on this device** remembers fitness entries in this browser; turn it off for temporary use. Export JSON backups regularly and use **Import backup** to restore them. Valid exports from the old `prep2026v2` planner are supported. **Clear all data** resets the fitness planner after confirmation. Exported files contain whatever you entered.

Local browser storage is not encrypted. Private browsing, storage restrictions, changing the folder location and browser-specific `file:` behavior can affect persistence. No entries are sent to a server. External links and references require a connection; the bundled pages and activities do not require a CDN or a build step.

The CTF and grade-login examples intentionally demonstrate insecure authorization using fictional data. They are learning simulations, not real accounts. BUNFI checks sample code patterns without running the submitted code.

## Verification

The original professional-section text, terminal structure and activity-feed content were compared with the source. JavaScript syntax, local assets/anchors, duplicate IDs and privacy metadata checks passed. Thirty-eight DOM interaction checks passed, including themes, fitness imports/exports/storage, CTF, all five BUNFI solutions, slides and the original graph model.

Tests used JSDOM and a headless Cytoscape model. Actual browser rendering, canvas appearance, CSP enforcement and direct-file persistence were not visually verified because the available browser could not open local files.

Optional local server: run `python -m http.server 8000 --bind 127.0.0.1` in this folder and open `http://127.0.0.1:8000/`.
