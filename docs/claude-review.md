# AttackFlow Code Review

**Reviewer**: Claude (Opus 4.6)  
**Date**: 2026-02-20  
**Version Audited**: 2.9.1  
**Scope**: Core HTML/JS files in root + `/stix-visualization` integration  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Security](#2-security)
3. [Consistency & Convention Compliance](#3-consistency--convention-compliance)
4. [Architecture & Design](#4-architecture--design)
5. [Code Quality](#5-code-quality)
6. [Data Pipeline & Integration](#6-data-pipeline--integration)
7. [Improvement Suggestions](#7-improvement-suggestions)

---

## 1. Executive Summary

AttackFlow is a zero-dependency vanilla JS browser application for mapping MITRE ATT&CK / CAPEC / CWE to Unified Kill Chain phases. The codebase shows strong security awareness — prototype pollution defenses, input sanitization, CSV formula injection prevention, CSP headers, and a well-designed MessageChannel-based IPC bridge. However, there are significant **duplication issues** across the STIX configuration layer, **overly aggressive sanitization** that silently corrupts legitimate data, and several **convention inconsistencies** between files that were clearly authored by different agents/sessions.

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High     | 6 |
| Medium   | 12 |
| Low      | 9 |
| Info     | 7 |

---

## 2. Security

### SEC-001 — Overly Aggressive Sanitization Strips Legitimate Data [HIGH]

**Files**: `index.html` (sanitizeImportedString), `stix-builder.html` (sanitizeImportedString, sanitizeUserInputText)

The `sanitizeImportedString()` function strips `[]{};"'` and `--` from all imported strings. This silently corrupts:

- **STIX Indicator patterns**: `[file:hashes.'SHA-256' = 'abc...']` → `file:hashes.SHA-256 = abc...`
- **CVSS vectors**: Already stripped by the time they reach storage (though vectors are separately validated in metadata)
- **JSON-embedded values**: Any field containing brackets, braces, or quotes
- **Legitimate descriptions**: "The attack used a 'zero-day' exploit" → "The attack used a zero-day exploit"
- **SQL-like content in analysis notes**: "Used query: SELECT -- comment" → "Used query: SELECT  comment"

The same sanitizer is reused for `sanitizeForStorage()` in the metadata editor, meaning user-typed comments lose these characters.

**Recommendation**: Replace blanket character stripping with context-aware sanitization. For HTML output, `escapeHtml()` already handles XSS. For attribute contexts, `escapeAttr()` handles injection. The character stripping should only apply to contexts where these characters are genuinely dangerous (e.g., innerHTML construction with unescaped interpolation).

### SEC-002 — InputSecurity.sanitize() Double-Encodes on Import [MEDIUM]

**File**: `index.html`

`sanitizeImportedString()` calls `.replace(/</g, '&lt;').replace(/>/g, '&gt;')` — encoding angle brackets in the stored data. Later, when rendering, `esc()` (which calls `escapeHtml()`) encodes them again, producing `&amp;lt;` in the output. This is a defense-in-depth measure but causes visible encoding artifacts in displayed text for any imported content containing `<` or `>`.

**Recommendation**: Store clean data, encode only at render time. The `esc()` call at render time already provides XSS protection.

### SEC-003 — stix-builder.html escapeHtml() Uses DOM Method [LOW]

**File**: `stix-builder.html` (InputSecurity.escapeHtml)

```js
escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}
```

This is functionally correct but creates a DOM element per call. In contrast, `index.html` uses a pure string replacement approach. The DOM method is slightly slower but not a security issue — it's a **consistency** issue (see CON-001).

### SEC-004 — Inline Event Handlers with String Interpolation [MEDIUM]

**File**: `index.html` (renderKillChain, renderEntityTag, filterEntities, renderGlobalSearchResults, buildPhaseDetails, etc.)

Extensive use of the following pattern throughout all rendering functions:

```js
onclick="openMetadataEditor('${escAttr(type)}', '${escAttr(id)}', '${escAttr(phaseKey)}', '${escAttr(instanceId)}')"
```

While `escAttr()` provides adequate protection, this pattern is inherently fragile — a single missed `escAttr()` call introduces DOM XSS. The `explorer.html` and `stix-builder.html` files use `addEventListener()` via DOM API instead, which is immune to this class of bugs.

**Recommendation**: For new code, prefer delegated event listeners (e.g., `data-action` + `data-*` attributes with a parent `addEventListener`), consistent with the pattern already used in `stix-builder.html`. Migrate inline handlers incrementally.

### SEC-005 — Content Security Policy Allows unsafe-inline [LOW]

**Files**: `index.html`, `explorer.html`, `stix-builder.html`

All three files set `script-src 'self' 'unsafe-inline'`. This is currently necessary because all JS is inline `<script>` blocks, but it negates much of CSP's XSS protection value. This is an architectural constraint rather than a bug.

**Recommendation**: If the application ever moves to external JS files, switch to hash-based or nonce-based CSP.

### SEC-006 — URL.createObjectURL() Not Cleaned Up on Error Path [LOW]

**File**: `index.html` (exportJSON, exportCSV, exportSTIXBundle)

The export functions create object URLs but if an error occurs between `createObjectURL()` and `revokeObjectURL()`, the blob URL leaks. This is a minor memory concern.

### SEC-007 — stix-visualization alert() for Errors [LOW]

**File**: `stix-visualization/stix_visualizer/application.js`

The bundled `alertException()` function uses `alert()` to display error messages. While this is the external library's code (and out of full audit scope), the integration doesn't intercept or override this — meaning parse errors from the visualizer will produce browser alert dialogs rather than toast notifications consistent with the rest of the UI.

### SEC-008 — Missing rel="noopener noreferrer" in index.html Rendered Links [MEDIUM]

**File**: `index.html`

Several rendered link templates in `index.html` use inline `onclick` handlers to open URLs rather than `<a>` tags, while others use `<a target="_blank">`. In functions like `buildEntityDetail()` and `renderRelationshipView()`, the `<a>` tags do include `rel="noopener noreferrer"`. However, in `renderKillChain()` entity tags, hyperlinks are rendered as clickable elements with `onclick="window.open('${url}', '_blank')"` which bypasses the `rel` protection.

**Recommendation**: Use `window.open(url, '_blank', 'noopener,noreferrer')` for all `window.open()` calls, or switch to `<a>` tags with proper `rel` attributes.

---

## 3. Consistency & Convention Compliance

### CON-001 — Duplicate STIX Configuration with Divergent Schemas [CRITICAL]

**Files**: `stix-config.js` vs `stix-builder.config.js`

Both files define STIX 2.1 object schemas, vocabularies, and common properties, but with significant divergences:

| Aspect | stix-config.js | stix-builder.config.js |
|--------|---------------|----------------------|
| **Scope** | SDOs only (19 types) | SDOs + SROs + SCOs + Markings + Extensions |
| **identity.identity_class** | Optional | **Required** |
| **grouping.context** | `type: 'open-vocab'` | `type: 'enum'` |
| **malware-analysis.result** | Required + `type: 'open-vocab'` | Required + `type: 'enum'` |
| **malware-analysis.product** | Required | Required (matches) |
| **Vocabularies** | 17 vocabularies | 20 vocabularies (adds `relationship-type-ov`, `hash-algorithm-ov`, `tlp-ov`) |
| **Common Properties** | `object_marking_refs: type 'list'`, `granular_markings: type 'list'` | `object_marking_refs: type 'object-marking-refs'`, `granular_markings: type 'granular-markings'` |
| **'use strict'** | Yes | Yes |
| **Category field** | No | Yes (per type: `sdo`, `sro`, `sco`, `marking`, `extension`) |
| **x-custom** | Included | Not included (no custom SDO type) |
| **External references** | In common optional properties | In common optional properties (matching) |
| **location.latitude/longitude** | `type: 'string'` | `type: 'number'` |

These divergences mean:
- An object valid in the Kill Chain Editor may fail validation in the STIX Composer
- Identity objects imported without `identity_class` will validate in index.html but fail in stix-builder.html
- Grouping context values are treated as free-text in one editor but constrained enum in another

**Recommendation**: Extract a single source-of-truth STIX schema file. Have `stix-config.js` export the SDO subset and `stix-builder.config.js` extend it with SROs/SCOs/markings. This is the highest-priority refactor.

### CON-002 — Duplicate STIX_ID_PATTERN Constant [HIGH]

**Files**: `stix-builder.config.js` (line 5), `index.html` (~line 4537)

```js
// stix-builder.config.js
const STIX_ID_PATTERN = /^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// index.html
const STIX_ID_PATTERN = /^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
```

Additionally, `stix-builder.html` defines:
```js
const ACTIVE_STIX_ID_PATTERN = (typeof STIX_ID_PATTERN !== 'undefined' && STIX_ID_PATTERN instanceof RegExp)
    ? STIX_ID_PATTERN : ...fallback...
```

Three definitions of the same regex across three files.

### CON-003 — Duplicate Relationship Mapping with Different Defaults [HIGH]

**Files**: `stix-config.js` (STIX_RELATIONSHIP_DEFAULTS), `index.html` (STIX_RELATIONSHIP_MAP)

```js
// stix-config.js — flat source→verb mapping
'attack-pattern': 'uses',        // Attack pattern "uses" something?
'campaign': 'uses',
'malware': 'uses',

// index.html — nested source→target→verb mapping  
STIX_RELATIONSHIP_MAP = {
    'attack-pattern': { 'malware': 'delivers', 'tool': 'uses', ... },
    ...
}
```

The flat mapping in `stix-config.js` is semantically incorrect for some types (an attack-pattern doesn't "use" things; it *is* used by actors). The nested mapping in `index.html` is more accurate but duplicates the concept. Neither file references the other.

### CON-004 — Massively Duplicated IPC Boilerplate [HIGH]

**Files**: `index.html`, `explorer.html`, `stix-builder.html`

Each file contains its own copy of:
- `IPC_BOOTSTRAP_MESSAGE_KEYS`, `IPC_CHANNEL_BOOTSTRAP_TYPE`, `IPC_BOOTSTRAP_WAIT_DEFAULTS`
- `logLocalIframeIPCSplash()`, `logLocalIframeIPCTrace()`
- `isLocalIframeIPCEnabled()`, `isLocalIframeIPCTraceEnabled()`
- `setParentIPCChannel()`, `clearParentIPCWaitTimer()`
- `getLocalIframeIPCBootstrapConfig()`, `estimateBootstrapFailureWindowMs()`
- `scheduleParentIPCBootstrapFailureWatch()`
- `hasOnlyAllowedKeys()`, `isPlainObject()`
- `DANGEROUS_OBJECT_KEYS`, `isDangerousObjectKey()`, `createSafeObject()`, `hasOwn()`, `parseJsonSafe()`, `stripAngleBracketsFromJson()`

This is ~200+ lines duplicated across three files. A shared utility file (e.g., `ipc-bridge.js`, `security-utils.js`) would eliminate this.

### CON-005 — Duplicate Theme System [MEDIUM]

**Files**: `index.html`, `explorer.html`, `stix-builder.html`

Each file repeats the full theme engine: `THEME_STORAGE_KEYS`, `currentTheme`, `getPreferredThemeMode()`, `normalizeThemeMode()`, `normalizeThemeScheme()`, `applyTheme()`, `updateThemeControls()`, `toggleThemeMode()`, `initThemeControls()`, `syncThemeFromStorage()`. The implementations are nearly identical but with minor variations.

### CON-006 — Duplicate InputSecurity Object [MEDIUM]

**Files**: `index.html`, `stix-builder.html`

Both define `InputSecurity` with `escapeHtml`, `encodeHtmlEntities`, `normalize`, `sanitize`, `sanitizeAttr`. The `index.html` version is more comprehensive (adds `validators` object). The `stix-builder.html` version uses a DOM-based `escapeHtml()` (SEC-003).

`explorer.html` takes a different approach — it tries to access `window.parent.InputSecurity` and falls back to a local `escapeHtml()` function.

### CON-007 — Duplicate enableLeaveSiteConfirmation() [LOW]

**Files**: `index.html`, `explorer.html`, `stix-builder.html`

Identical `enableLeaveSiteConfirmation()` function in all three files.

### CON-008 — Mixed Confirmation Patterns [LOW]

**File**: `index.html`

- `removeAssignment()`: `window.confirm('Remove this item?')`
- `clearAssignments()`: `confirm('Clear all assignments...')`
- `removeGroup()`: `window.confirm('Remove this group...')`

Inconsistent use of `window.confirm()` vs `confirm()` (functionally identical but stylistically inconsistent).

### CON-009 — Inconsistent escapeHtml Naming [LOW]

| File | Function Names |
|------|---------------|
| `index.html` | `esc()` → `InputSecurity.escapeHtml()`, `escAttr()` → `InputSecurity.sanitizeAttr()` |
| `explorer.html` | `escapeHtml()`, `escapeAttr()` |
| `stix-builder.html` | `esc()` → `InputSecurity.escapeHtml()`, `escAttr()` → `InputSecurity.sanitizeAttr()` |

Three different naming conventions for the same operation.

### CON-010 — Missing 'use strict' in index.html [MEDIUM]

**File**: `index.html`

The inline `<script>` block (~6,000 lines of JS) does not use `'use strict'`. Both `stix-config.js` and `stix-builder.config.js` have `'use strict'`. This means silent errors from accidental globals, duplicate parameter names, and other sloppy-mode foot-guns are possible in the largest file.

---

## 4. Architecture & Design

### ARCH-001 — Monolithic index.html [INFO]

`index.html` contains ~10,500 lines with ~6,500 lines of inline JavaScript. While the section banners (`// ====...====`) provide orientation, the single-file approach makes it difficult to:
- Run static analysis tools
- Apply tree-shaking or code splitting
- Test individual functions in isolation
- Track changes in version control (merge conflicts are almost guaranteed)

The copilot-instructions acknowledge this as intentional (zero-dependency, no build step), so this is noted as architectural context rather than a defect.

### ARCH-002 — Global Scope for Everything [INFO]

All functions, constants, and the `state` object live in global scope within `index.html`. This works because the application is a single page, but it means:
- Any browser extension or injected script can mutate `state` directly
- Name collisions between sections are possible (and have occurred — see CON-002)
- No encapsulation of internal vs. public API

### ARCH-003 — No Error Boundaries in Rendering [MEDIUM]

**File**: `index.html`

The rendering functions (`renderKillChain()`, `filterEntities()`, `renderRelationshipView()`, `renderStats()`, `renderGlobalSearchResults()`, etc.) lack try/catch wrappers. A malformed entity or corrupt state property will crash the render cycle with an unhandled exception, potentially leaving the DOM in a partial-render state.

`renderAll()` calls `filterEntities()` four times, `renderKillChain()`, `syncTitleToDOM()`, and `syncDescriptionToDOM()`. A failure in any of these aborts the rest.

**Recommendation**: Wrap each render call in `renderAll()` with try/catch and display a toast on error:
```js
function renderAll() {
    const tasks = [
        () => filterEntities('attack'),
        () => filterEntities('capec'),
        () => filterEntities('cwe'),
        () => filterEntities('custom'),
        () => renderKillChain(),
        () => syncTitleToDOM(),
        () => syncDescriptionToDOM()
    ];
    for (const task of tasks) {
        try { task(); } catch (e) { console.error('Render error:', e); }
    }
}
```

### ARCH-004 — STIX Bundle Build Ignores CAPEC/CWE Items [MEDIUM]

**File**: `index.html` (buildSTIXBundle)

`buildSTIXBundle()` generates STIX SDOs for assigned ATT&CK techniques (as `attack-pattern`) and custom items, but does **not** generate SDOs for assigned CAPEC or CWE items. These framework items are simply omitted from the exported STIX bundle, meaning a kill chain with CAPEC-123 assigned to a phase won't have that item represented in the STIX output.

**Recommendation**: Generate `attack-pattern` SDOs for CAPEC items (they map to STIX attack-patterns via external references) and `weakness` or `vulnerability` SDOs for CWE items.

### ARCH-005 — stix-builder.html Loads Visualizer Eagerly [LOW]

**File**: `stix-builder.html` (lines 41-56)

The `configureStixVisualizerAvailability()` IIFE injects the visualizer CSS and require.js script into the `<head>` at page load, even if the user never switches to visualizer mode. The vis.js network library is substantial.

**Recommendation**: Lazy-load visualizer resources only when the user first clicks "Visualizer" mode.

### ARCH-006 — Explorer URL Parameter Parsing Without Validation [LOW]

**File**: `explorer.html`

```js
const params = new URLSearchParams(window.location.search);
const entityParam = params.get('entity');
if (entityParam) {
    const [typeRaw, ...rest] = entityParam.split(':');
    const type = typeRaw?.toLowerCase();
    const id = rest.join(':');
```

The `id` value from URL params is used directly to look up `store[id]` without sanitization. While it's only used as a key lookup (not rendered unsanitized), the lack of format validation means any string could be passed as an ID.

---

## 5. Code Quality

### CQ-001 — removeGroup() Uses Hardcoded Keys Instead of TYPE_KEYS [HIGH]

**File**: `index.html`

```js
function removeGroup(phaseKey, groupId) {
    const phase = state.assignments[phaseKey];
    const group = (phase.groups || []).find(g => g.groupId === groupId);
    if (!group) return;
    // Redistribute items back to phase-level arrays by type
    for (const item of group.items || []) {
        const key = item.type === 'attack' ? 'techniques'
                  : item.type === 'capec' ? 'capecs'
                  : item.type === 'cwe' ? 'cwes'
                  : null;
        if (key && phase[key]) {
            phase[key].push(item);
        }
    }
```

This ternary chain:
1. Doesn't handle `type === 'custom'` — custom items in groups are silently dropped when ungrouping
2. Hardcodes the type→key mapping instead of using the `TYPE_KEYS` constant defined elsewhere in the same file

### CQ-002 — generateUUID() Uses Math.random() [MEDIUM]

**Files**: `index.html`, `stix-builder.html`

```js
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = Math.random() * 16 | 0;
        ...
    });
}
```

`Math.random()` is not cryptographically secure. While UUIDs here are not used for security purposes, STIX IDs are meant to be globally unique. `crypto.getRandomValues()` would provide better uniqueness guarantees. `index.html` actually has a `generateUUID()` that uses `crypto.getRandomValues()` with a `Math.random()` fallback — but `stix-builder.html` only has the `Math.random()` version.

### CQ-003 — Inconsistent UUID Generation Implementations [MEDIUM]

**File**: `index.html` has two UUID implementations:
1. `generateUUID()` — uses `crypto.getRandomValues()` with fallback
2. `generateUUIDv5()` — inline SHA-1 implementation for deterministic STIX IDs

`stix-builder.html` has only:
1. `generateUUID()` — uses `Math.random()` only (no crypto fallback)

### CQ-004 — Deep Nesting in sanitizeAssignmentMetadata() [LOW]

**File**: `index.html`

`sanitizeAssignmentMetadata()` is ~100 lines covering CVE entries, hyperlinks, observables, comments, score, and confidence. The CVE handling alone has 4 levels of nesting with multiple format migrations (cveEntries, cveIds, legacy cveId/cve + cvssVector). This would benefit from extraction into focused helper functions.

### CQ-005 — Magic Numbers in Import Validation [LOW]

**File**: `index.html`

```js
const KILLCHAIN_IMPORT_LIMITS = {
    maxFileSize: 5 * 1024 * 1024,  // 5 MB
    maxAssignmentsPerPhase: 500,
    maxHyperlinks: 50,
    maxObservables: 100,
    maxStringLength: 5000
};
```

These limits are defined locally but partially overlap with `CONFIG.display.*` limits and `stix-builder.html`'s `INPUT_LIMITS`. Should be centralized in `config.js`.

### CQ-006 — Unused STIX_RELATIONSHIP_DEFAULTS [LOW]

**File**: `stix-config.js`

`STIX_RELATIONSHIP_DEFAULTS` is defined and exported but never referenced by `index.html` (which uses its own `STIX_RELATIONSHIP_MAP` instead). It's also not used by `stix-builder.html` (which loads `stix-builder.config.js`, not `stix-config.js`).

### CQ-007 — ensureAssignmentShape() Doesn't Rebuild Layout [LOW]

**File**: `index.html`

`ensureAssignmentShape()` calls `ensurePhaseLayout(phaseKey, phaseData)` at the end, which should rebuild the layout. However, if groups have been modified (e.g., items redistributed), the layout may contain stale references to group IDs that no longer exist.

### CQ-008 — renderDescriptionWithBadges() Regex Coupling [INFO]

**File**: `explorer.html`

The regex in `renderDescriptionWithBadges()` is tightly coupled to MITRE's URL format:
```js
/\[([^\]]{1,80})\]\(https?:\/\/attack\.mitre\.org\/techniques\/(T\d{4}(?:\/\d{3})?)\)/g
```

This only handles technique cross-references. CAPEC and CWE links in descriptions use different URL formats and are not converted to badges.

---

## 6. Data Pipeline & Integration

### DP-001 — stix-visualization Integration is Minimal but Clean [INFO]

The integration between `stix-builder.html` and the bundled `stix-visualization` library is well-executed:
- The library exposes `window.AttackFlowStixViz` API with `render()`, `reset()`, `applyTheme()`, `select()`, `selectAndPopulate()`, and an `onSelect` callback
- `stix-builder.html` passes sanitized bundles via `sanitizeBundleForVisualizer()` before rendering
- Theme synchronization is handled via `applyThemeToGraph()` which reads CSS custom properties
- The `configureStixVisualizerAvailability()` guard respects `CONFIG.visualizer.enabled`
- Uploader/paste UI elements from the original library are hidden via CSS (`display: none`)
- Icon directory is hard-coded to the correct relative path

No injection points or unsafe data flow between the host and the library.

### DP-002 — IPC Bridge Design is Solid [INFO]

The parent→child IPC system is well-engineered:
- **Channel isolation**: MessageChannel with transferred ports (not `window.postMessage` broadcast)
- **Nonce binding**: Each channel has a unique nonce; messages with wrong nonce are rejected
- **Schema enforcement**: Inbound/outbound message types have allowlisted key sets (`hasOnlyAllowedKeys()`)
- **Rate limiting**: Token-bucket algorithm in parent for outbound request throttling
- **Bootstrap retry with backoff**: Configurable timeout, max retries, exponential backoff, grace period
- **Data freezing**: Shared data from parent is `deepFreeze()`-ed before use in explorer
- **Source pinning**: Messages only accepted from `window.parent`

The only concern is the massive code duplication (CON-004).

### DP-003 — Explorer Fallback to Direct Parent Access in file:// Mode [LOW]

**File**: `explorer.html`

```js
const _parentSec = (function () {
    if (!isLocalIframeIPCEnabled()) return null;
    try { return window.parent?.InputSecurity; } catch (e) { return null; }
})();
```

In `file://` mode, `explorer.html` reaches directly into the parent frame for `InputSecurity`. This bypasses the IPC channel (which is the intended mechanism) and creates a coupling between parent and child frame internals. However, `getParentSharedDataLoader()` correctly returns `null` in channel-only mode, so this only affects the escaping function.

### DP-004 — No Validation of stix-builder.config.js Load [MEDIUM]

**File**: `stix-builder.html`

The initialization sequence:
```js
if (!Object.keys(ACTIVE_STIX_OBJECT_DEFS).length) {
    updateStatus(false, 'STIX config failed to load');
    showToast('Error: STIX configuration unavailable');
    initEvents();
} else {
    buildAddTypeOptions();
}
```

If `stix-builder.config.js` fails to load (network error, parse error), the entire STIX Composer is non-functional but still renders its empty UI. The error indication is only a toast + status dot — easy to miss. There's no retry mechanism or prominent error state.

---

## 7. Improvement Suggestions

### IMP-001 — Extract Shared Utilities [HIGH PRIORITY]

Create shared JS files to eliminate the ~400+ lines of duplicated code:

```
shared/
  security.js      — InputSecurity, DANGEROUS_OBJECT_KEYS, parseJsonSafe, stripAngleBracketsFromJson, etc.
  ipc-common.js    — IPC constants, bootstrap helpers, logging
  theme.js         — Theme engine (already nearly identical across all 3 files)
  stix-schema.js   — Single source of truth for STIX schemas (merge stix-config.js + stix-builder.config.js)
```

Each HTML file would include: `<script src="shared/security.js"></script>` etc. This maintains the zero-build constraint while eliminating duplication.

### IMP-002 — Unify STIX Schema [CRITICAL PRIORITY]

Merge `stix-config.js` and `stix-builder.config.js` into a single schema definition. The builder config can extend the base with SROs/SCOs/markings:

```js
// stix-schema.js — base SDO definitions (current stix-config.js content)
// stix-builder-extensions.js — adds SROs, SCOs, markings, JSON schema
```

Ensure field types (`enum` vs `open-vocab`, `required` vs `optional`) are consistent.

### IMP-003 — Add Error Boundaries to Rendering Pipeline [MEDIUM PRIORITY]

Wrap rendering functions to prevent cascading failures. A single corrupt entity should not crash the entire kill chain view.

### IMP-004 — Migrate Inline Event Handlers [LOW PRIORITY]

For new code, adopt the delegated event listener pattern used in `stix-builder.html`:
```js
document.getElementById('editor-panel').addEventListener('click', handleEditorClick);
```

This eliminates the need for `escAttr()` in `onclick` attributes and makes event handling testable.

### IMP-005 — Add Input Limits to config.js [LOW PRIORITY]

Centralize all `maxFileSize`, `maxObjects`, `maxStringLength`, `maxAssignmentsPerPhase`, etc. into `CONFIG.limits` rather than having separate `KILLCHAIN_IMPORT_LIMITS` and `INPUT_LIMITS` constants scattered across files.

### IMP-006 — STIX Bundle Export for CAPEC/CWE [MEDIUM PRIORITY]

Extend `buildSTIXBundle()` to generate STIX objects for assigned CAPEC patterns (as `attack-pattern` with CAPEC external references) and CWE weaknesses (as `vulnerability` or a custom extension with CWE external references).

### IMP-007 — Lazy-Load Visualizer [LOW PRIORITY]

Defer loading of the `stix-visualization` library's CSS and require.js until the user activates visualizer mode. This reduces initial page load for the majority use case.

---

## Appendix A — Files Audited

| File | Lines | Role |
|------|-------|------|
| `config.js` | 291 | Central configuration, theme engine |
| `stix-config.js` | 576 | STIX SDO schemas for Kill Chain Editor |
| `stix-builder.config.js` | 827 | STIX schemas for STIX Composer (SDOs + SROs + SCOs + markings) |
| `index.html` | 10,512 | Main monolith — UI, state, rendering, IPC parent, import/export |
| `explorer.html` | 1,776 | Relationship Explorer — IPC child, entity browsing |
| `stix-builder.html` | 2,838 | STIX Composer — IPC child, bundle editing, visualizer integration |
| `stix-visualization/stix_visualizer/application.js` | 915 | Bundled visualizer — integration API only |

## Appendix B — Cross-Reference of Duplicated Functions

| Function/Constant | index.html | explorer.html | stix-builder.html |
|-------------------|:----------:|:-------------:|:-----------------:|
| `THEME_STORAGE_KEYS` | ✓ | ✓ | ✓ |
| `getPreferredThemeMode()` | ✓ | ✓ | ✓ |
| `normalizeThemeMode()` | ✓ | ✓ | ✓ |
| `normalizeThemeScheme()` | ✓ | ✓ | ✓ |
| `applyTheme()` | ✓ | ✓ | ✓ |
| `initThemeControls()` | ✓ | ✓ | ✓ |
| `syncThemeFromStorage()` | ✓ | ✓ | ✓ |
| `isLocalIframeIPCEnabled()` | ✓ | ✓ | ✓ |
| `logLocalIframeIPCSplash()` | ✓ | ✓ | ✓ |
| `logLocalIframeIPCTrace()` | ✓ | ✓ | ✓ |
| `isPlainObject()` | ✓ | ✓ | ✓ |
| `hasOnlyAllowedKeys()` | ✓ | ✓ | ✓ |
| `DANGEROUS_OBJECT_KEYS` | ✓ | ✓ | ✓ |
| `parseJsonSafe()` | ✓ | ✓ | ✓ |
| `enableLeaveSiteConfirmation()` | ✓ | ✓ | ✓ |
| `STIX_ID_PATTERN` | ✓ | — | ✓ (via config) |
| `generateUUID()` | ✓ | — | ✓ |
| `InputSecurity` | ✓ | partial | ✓ |
| `sanitizeImportedString()` | ✓ | — | ✓ |
| `applyInputGuards()` | ✓ | — | ✓ |
| `isSafeHttpUrl()` | — | ✓ | ✓ |
| `IPC_BOOTSTRAP_WAIT_DEFAULTS` | ✓ | ✓ | ✓ |
| `getLocalIframeIPCBootstrapConfig()` | ✓ | ✓ | ✓ |
| `estimateBootstrapFailureWindowMs()` | ✓ | ✓ | ✓ |
| `setParentIPCChannel()` | ✓ | ✓ | ✓ |
| `stripAngleBracketsFromJson()` | ✓ | — | ✓ |
