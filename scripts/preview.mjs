#!/usr/bin/env node
'use strict';

/*
 * Renders a PNG as ASCII art so the artwork can be checked in the terminal.
 *
 *   node scripts/preview.mjs <file.png> [cols]
 *
 * Prints luminance ramp art. Good enough to judge whether a mark reads as
 * intended at a glance, which is the point.
 */

import { readFileSync } from 'node:fs';
import { decode, average } from './png.mjs';

const file = process.argv[2];
const cols = Number(process.argv[3]) || 60;

if (!file) {
  console.error('usage: node scripts/preview.mjs <file.png> [cols]');
  process.exit(1);
}

const img = decode(readFileSync(file));
const aspect = img.height / img.width;
const rows = Math.max(1, Math.round(cols * aspect * 0.5)); // terminal cells are ~2:1

const RAMP = ' .:-=+*#%@';

// In "shape" mode the glyph is found by how far a cell differs from the corner
// colour, which reads far better than luminance when a light mark sits on a
// coloured background.
const shape = process.argv.includes('--shape');
const bg = average(img, 0, 0, Math.max(1, img.width >> 2), Math.max(1, img.height >> 2));

let out = `${img.width}x${img.height} -> ${cols}x${rows}  bg=rgb(${bg.r | 0},${bg.g | 0},${bg.b | 0})\n`;
for (let ry = 0; ry < rows; ry += 1) {
  const y0 = Math.floor((ry * img.height) / rows);
  const y1 = Math.max(y0 + 1, Math.floor(((ry + 1) * img.height) / rows));
  let line = '';
  for (let rx = 0; rx < cols; rx += 1) {
    const x0 = Math.floor((rx * img.width) / cols);
    const x1 = Math.max(x0 + 1, Math.floor(((rx + 1) * img.width) / cols));
    const c = average(img, x0, y0, x1, y1);

    if (shape) {
      const dist = Math.hypot(c.r - bg.r, c.g - bg.g, c.b - bg.b);
      const pct = Math.min(1, dist / 150);
      line += pct < 0.12 ? ' ' : pctlamp(pct);
    } else {
      const alpha = c.a / 255;
      const lum = (0.2126 * c.r + 0.7152 * c.g + 0.0722 * c.b) * alpha + 255 * (1 - alpha);
      const idx = Math.min(RAMP.length - 1, Math.max(0, Math.round(((255 - lum) / 255) * (RAMP.length - 1))));
      line += alpha < 0.05 ? ' ' : RAMP[idx];
    }
  }
  out += `${line.replace(/\s+$/, '')}\n`;
}

function pctlamp(pct) {
  return '@#*:. '[Math.min(4, Math.floor(pct * 5))];
}

process.stdout.write(out);

// A crude "is anything there" check, so a blank render is obvious.
let opaque = 0;
for (let i = 3; i < img.data.length; i += 4) if (img.data[i] > 8) opaque += 1;
console.log(`coverage: ${((opaque / (img.width * img.height)) * 100).toFixed(1)}%`);