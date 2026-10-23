// Environment control for single cases (docs/04 section 2, item 6).
//
// Most of the suite runs against pinned values; a case that must measure what
// the application ships removes the key from process.env so config/defaults.js
// decides, then restores it. Nothing here mutates the .env file.

const saved = new Map();

/** Remove keys from process.env for this case. Returns a restore function. */
export function clearKeys(keys) {
  for (const key of keys) {
    if (!saved.has(key)) saved.set(key, process.env[key]);
    delete process.env[key];
  }
  return restore;
}

/** Set keys for this case. Returns a restore function. */
export function setKeys(values) {
  for (const [key, value] of Object.entries(values)) {
    if (!saved.has(key)) saved.set(key, process.env[key]);
    process.env[key] = String(value);
  }
  return restore;
}

export function restore() {
  for (const [key, value] of saved.entries()) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  saved.clear();
}
