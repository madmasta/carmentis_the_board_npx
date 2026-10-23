// Deterministic fault seam for the 500 error path (docs/01 section 5).
//
// Without it, probing "does the error page leak internals?" needs a handler that
// is actually broken, which would put a real bug in the control build. The
// pipeline rethrows the armed fault on the next request exactly once; nothing in
// src/ ever arms it, and controls.test.mjs#c-info-1 asserts that fact.

let armed = null;

export function setTestFault(fnOrNull = null) {
  armed = typeof fnOrNull === 'function' ? fnOrNull : null;
}

export function faultIsArmed() {
  return armed !== null;
}

/** Called by the request pipeline; consumes the fault and throws it. */
export function consumeFault() {
  if (armed === null) return;
  const factory = armed;
  armed = null;
  throw factory();
}
