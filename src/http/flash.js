// One-shot flash messages, stored in the session payload (docs/02 B14).
// Port of src/Flash.php: the queue is consumed by the next render, so a message
// is shown exactly once.

const TYPES = new Set(['success', 'error', 'info']);

export function addFlash(session, type, message) {
  if (!session.data) session.data = {};
  if (!Array.isArray(session.data.flash)) session.data.flash = [];
  session.data.flash.push({ type: TYPES.has(type) ? type : 'info', message: String(message) });
}

/** Read and clear the queue. Called once per render. */
export function takeFlash(session) {
  const queue = Array.isArray(session?.data?.flash) ? session.data.flash : [];
  if (session?.data) session.data.flash = [];
  return queue;
}

export function peekFlash(session) {
  return Array.isArray(session?.data?.flash) ? session.data.flash : [];
}
