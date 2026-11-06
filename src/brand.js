'use strict';

const fs = require('node:fs');
const path = require('node:path');

const VERSION_RE = /const BRAND_VERSION = (\d+)\s*;/;

/**
 * Reads the BRAND_VERSION literal out of a views.js source string.
 * Returns null when the declaration is absent.
 */
function parseBrandVersion(source) {
  if (typeof source !== 'string') return null;
  const match = VERSION_RE.exec(source);
  if (!match) return null;
  return Number(match[1]);
}

/** Reads the ?v= on the first manifest icon. Returns null when it is absent. */
function parseManifestVersion(manifestText) {
  if (typeof manifestText !== 'string' || manifestText.trim() === '') return null;
  let parsed;
  try {
    parsed = JSON.parse(manifestText);
  } catch {
    return null;
  }
  const src = parsed?.icons?.[0]?.src;
  if (typeof src !== 'string') return null;
  const match = /[?&]v=(\d+)/.exec(src);
  return match ? Number(match[1]) : null;
}

/**
 * Compares the brand version this process loaded with what a restart would
 * read from disk.
 *
 * The inlined mark and the on-disk asset cache both live for the life of the
 * process. Replacing the files, or even re-requiring them in another part of
 * a long-running process, does not change what this process serves. This
 * helper only reports that. It never throws and never refuses to start:
 * a missing file is a flag, not a fatal error.
 *
 * @param {object} input
 * @param {number} input.loadedVersion BRAND_VERSION from the already-loaded module
 * @param {string} input.viewsPath path to src/views.js
 * @param {string} input.manifestPath path to site.webmanifest
 * @param {function} [input.readFile]
 */
function checkBrandVersions({ loadedVersion, viewsPath, manifestPath, readFile = fs.readFileSync }) {
  const result = {
    loadedVersion: Number(loadedVersion),
    sourceVersion: null,
    manifestVersion: null,
    sourceUnreadable: false,
    manifestUnreadable: false,
    restartRequired: false,
    manifestDrift: false,
  };

  try {
    result.sourceVersion = parseBrandVersion(readFile(viewsPath, 'utf8'));
  } catch {
    result.sourceUnreadable = true;
  }
  try {
    result.manifestVersion = parseManifestVersion(readFile(manifestPath, 'utf8'));
  } catch {
    result.manifestUnreadable = true;
  }

  if (result.sourceVersion !== null && result.sourceVersion !== result.loadedVersion) {
    // Disk has a different declaration than the module this process evaluated
    // at startup. Only a restart serves the disk version.
    result.restartRequired = true;
  }
  if (result.manifestVersion !== null && result.manifestVersion !== result.loadedVersion) {
    result.manifestDrift = true;
  }

  return result;
}

/** The check against this installation's views.js and manifest. */
function checkInstalledBrand(loadedVersion) {
  return checkBrandVersions({
    loadedVersion,
    viewsPath: path.join(__dirname, 'views.js'),
    manifestPath: path.join(__dirname, '..', 'public', 'branding', 'site.webmanifest'),
  });
}

/**
 * One log line. Warnings are for a real disagreement; the steady state still
 * says that a later brand change needs a restart, because that is the step
 * people skip.
 */
function formatBrandLog(status) {
  if (status.restartRequired) {
    const manifestNote =
      status.manifestDrift && status.manifestVersion !== null
        ? ` site.webmanifest on disk is ?v=${status.manifestVersion}.`
        : '';
    return (
      `[paste] BRAND_VERSION mismatch: this process is serving ${status.loadedVersion}, ` +
      `but src/views.js on disk says ${status.sourceVersion}.` +
      manifestNote +
      ` The inlined mark and ?v= tags stay on ${status.loadedVersion} until you restart. ` +
      `Reloading the files without a restart does not pick the disk version up.`
    );
  }
  if (status.manifestDrift) {
    return (
      `[paste] brand version drift: this process serves BRAND_VERSION=${status.loadedVersion}, ` +
      `but site.webmanifest is ?v=${status.manifestVersion}. ` +
      `Bump them together and restart, or the page and the edge icons disagree.`
    );
  }
  const manifest =
    status.manifestVersion !== null ? ` and manifest ?v=${status.manifestVersion}` : '';
  return (
    `[paste] brand version ${status.loadedVersion} (process matches src/views.js${manifest}). ` +
    `Restart after any BRAND_VERSION or brand/ change: the inlined mark and the asset cache are not reloaded.`
  );
}

module.exports = {
  parseBrandVersion,
  parseManifestVersion,
  checkBrandVersions,
  checkInstalledBrand,
  formatBrandLog,
};
