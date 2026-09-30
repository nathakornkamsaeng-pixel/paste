'use strict';

const fs = require('node:fs');
const path = require('node:path');

const config = require('./config');

const hljs = require(path.join(config.hljsDir, 'lib', 'index.js'));

// Highlighting is by far the most expensive thing this process does, so pastes
// above this size are rendered as plain escaped text instead.
const MAX_HIGHLIGHT_BYTES = 200_000;

const EXTENSION_LANGUAGES = new Map(
  Object.entries({
    js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
    ts: 'typescript', tsx: 'typescript',
    py: 'python', rb: 'ruby', rs: 'rust', go: 'go',
    c: 'c', h: 'c', cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp',
    cs: 'csharp', java: 'java', kt: 'kotlin', swift: 'swift',
    php: 'php', pl: 'perl', lua: 'lua', r: 'r',
    sh: 'bash', bash: 'bash', zsh: 'bash', fish: 'bash',
    ps1: 'powershell', bat: 'dos', cmd: 'dos',
    sql: 'sql', html: 'xml', htm: 'xml', xml: 'xml', svg: 'xml', vue: 'xml',
    css: 'css', scss: 'scss', sass: 'scss', less: 'less',
    json: 'json', jsonc: 'json', yaml: 'yaml', yml: 'yaml', toml: 'ini', ini: 'ini',
    md: 'markdown', markdown: 'markdown',
    dockerfile: 'dockerfile', tf: 'hcl', hcl: 'hcl',
    diff: 'diff', patch: 'diff',
    tex: 'latex', bib: 'latex',
    vim: 'vim', nginx: 'nginx', apache: 'apacheconf', graphql: 'graphql',
    proto: 'protobuf', scala: 'scala', hs: 'haskell', ex: 'elixir', exs: 'elixir',
    erl: 'erlang', clj: 'clojure', zig: 'zig', nim: 'nim', dart: 'dart',
  }),
);

const SUPPORTED = (() => {
  const names = new Set();
  for (const lang of hljs.listLanguages()) names.add(lang.toLowerCase());
  return names;
})();

/** Maps a user-supplied language name onto one highlight.js recognises. */
function normaliseLanguage(input, filename) {
  if (typeof input === 'string' && input.trim()) {
    const wanted = input.trim().toLowerCase();
    if (SUPPORTED.has(wanted)) return wanted;
    const alias = EXTENSION_LANGUAGES.get(wanted);
    if (alias && SUPPORTED.has(alias)) return alias;
  }
  return languageFromFilename(filename);
}

function languageFromFilename(filename) {
  if (typeof filename !== 'string' || !filename) return null;
  const ext = path.extname(filename).replace(/^\./, '').toLowerCase();
  if (!ext) {
    const base = filename.toLowerCase();
    if (['dockerfile', 'makefile'].includes(base)) return base === 'dockerfile' ? 'dockerfile' : 'makefile';
    return null;
  }
  const mapped = EXTENSION_LANGUAGES.get(ext);
  if (mapped && SUPPORTED.has(mapped)) return mapped;
  return SUPPORTED.has(ext) ? ext : null;
}

/**
 * Returns HTML for the paste body.
 *
 * highlight.js escapes the code as it tokenises, so the returned markup is
 * safe to inject directly. The size cap keeps a single pathological paste from
 * stalling the event loop; pastes over it fall back to escaped plain text,
 * which is also produced by an escaping function rather than by string
 * concatenation of raw input.
 */
function render(content, language) {
  const source = String(content);

  if (Buffer.byteLength(source, 'utf8') > MAX_HIGHLIGHT_BYTES) {
    return { html: `<pre class="plain"><code>${escapeHtml(source)}</code></pre>`, truncated: true };
  }

  if (language && SUPPORTED.has(language)) {
    try {
      const { value } = hljs.highlight(source, { language, ignoreIllegals: true });
      return { html: `<pre class="code"><code class="hljs language-${escapeHtml(language)}">${value}</code></pre>`, truncated: false };
    } catch {
      // Fall through to the escaping path below.
    }
  }

  try {
    const result = hljs.highlightAuto(source.slice(0, 40_000));
    if (result.relevance > 5 && result.language) {
      return { html: `<pre class="code"><code class="hljs language-${escapeHtml(result.language)}">${result.value}</code></pre>`, truncated: false, detected: result.language };
    }
  } catch {
    // Auto-detection is best effort only.
  }

  return { html: `<pre class="plain"><code>${escapeHtml(source)}</code></pre>`, truncated: false };
}

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => HTML_ESCAPES[char]);
}

/**
 * Splits source into numbered lines for the plain-text rendering path.
 * Kept separate from render() so the line-number gutter can be emitted without
 * another pass over the string.
 */
function lineNumbers(count) {
  const width = String(Math.max(1, count)).length;
  const out = [];
  for (let i = 1; i <= count; i += 1) out.push(String(i).padStart(width, ' '));
  return out;
}

/**
 * The vendored highlight.js stylesheet, read once at boot.
 *
 * A light theme on purpose: the site itself is light, and a dark code block in
 * a light page reads as a mistake. github.css is also the closest match to the
 * surrounding surfaces.
 */
function stylesheet() {
  return fs.readFileSync(path.join(config.hljsDir, 'styles', 'github.css'), 'utf8');
}

module.exports = { render, escapeHtml, normaliseLanguage, languageFromFilename, stylesheet, lineNumbers };