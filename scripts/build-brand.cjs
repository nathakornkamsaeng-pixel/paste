#!/usr/bin/env node
'use strict';

/*
 * Renders the brand set into public/branding.
 *
 *   node scripts/build-brand.mjs
 *
 * Requires rsvg-convert (apt install librsvg2-bin) and the Inter family for
 * the wordmark; without Inter it silently falls back to DejaVu, which still
 * renders but looks less like the site.
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const brandDir = path.join(__dirname, '..', 'brand');
const outDir = path.join(__dirname, '..', 'public', 'branding');
fs.mkdirSync(outDir, { recursive: true });

function render(svg, width, height, out) {
  execFileSync(
    'rsvg-convert',
    ['-w', String(width), '-h', String(height), '-o', out, path.join(brandDir, svg)],
    { stdio: ['ignore', 'ignore', 'inherit'] },
  );
  return out;
}

/**
 * Packs PNGs into a classic .ico. Each entry embeds a whole PNG, which every
 * browser since IE11 understands and which keeps the alpha channel intact.
 */
function writeIco(entries, out) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // type: icon
  header.writeUInt16LE(entries.length, 4);

  const dir = Buffer.alloc(16 * entries.length);
  let offset = header.length + dir.length;

  entries.forEach((entry, i) => {
    const data = fs.readFileSync(entry.file);
    const at = i * 16;
    // 0 is the documented encoding for 256px.
    dir.writeUInt8(entry.size >= 256 ? 0 : entry.size, at);
    dir.writeUInt8(entry.size >= 256 ? 0 : entry.size, at + 1);
    dir.writeUInt8(0, at + 2); // palette size
    dir.writeUInt8(0, at + 3); // reserved
    dir.writeUInt16LE(1, at + 4); // colour planes
    dir.writeUInt16LE(32, at + 6); // bits per pixel
    dir.writeUInt32LE(data.length, at + 8);
    dir.writeUInt32LE(offset, at + 12);
    offset += data.length;
    entry.data = data;
  });

  fs.writeFileSync(out, Buffer.concat([header, dir, ...entries.map((e) => e.data)]));
}

const built = [];

// Favicon and touch icons, straight from the mark.
const png16 = render('icon.svg', 16, 16, path.join(outDir, 'favicon-16.png'));
const png32 = render('icon.svg', 32, 32, path.join(outDir, 'favicon-32.png'));
const png48 = render('icon.svg', 48, 48, path.join(outDir, 'favicon-48.png'));
built.push('favicon-16.png', 'favicon-32.png', 'favicon-48.png');

writeIco(
  [16, 32, 48].map((size) => ({ size, file: path.join(outDir, `favicon-${size}.png`) })),
  path.join(outDir, 'favicon.ico'),
);
built.push('favicon.ico');

// Modern browsers take the SVG directly; keep it flat for crispness at 16px.
fs.copyFileSync(path.join(brandDir, 'favicon.svg'), path.join(outDir, 'favicon.svg'));
built.push('favicon.svg');

render('icon.svg', 180, 180, path.join(outDir, 'apple-touch-icon.png'));
built.push('apple-touch-icon.png');

render('icon.svg', 192, 192, path.join(outDir, 'icon-192.png'));
render('icon.svg', 512, 512, path.join(outDir, 'icon-512.png'));
built.push('icon-192.png', 'icon-512.png');

render('og.svg', 1200, 630, path.join(outDir, 'og.png'));
built.push('og.png');

render('logo.svg', 650, 240, path.join(outDir, 'logo.png'));
built.push('logo.png');

console.log(`brand assets -> ${path.relative(process.cwd(), outDir)}`);
for (const name of built) {
  const size = fs.statSync(path.join(outDir, name)).size;
  console.log(`  ${name.padEnd(24)} ${String(size).padStart(7)} B`);
}