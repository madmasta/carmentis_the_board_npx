// Hook routes (docs/02 section 7). Every one of these is Node-only: the PHP
// target has no equivalent, so nothing here is a port — what is pinned is the
// failure contract in docs/02 section 7 and the control each row names in
// docs/03. Each handler does its own authority and input checks; the route table
// declares the guard that the pipeline enforces first.

import * as boards from '../repositories/board.repository.js';
import * as postsRepo from '../repositories/post.repository.js';
import * as users from '../repositories/user.repository.js';
import { exportBoard, importBoard } from '../xml/bridge.js';
import { list as directoryList } from '../hooks/directory.js';
import { search as xpathSearch } from '../hooks/xpath.js';
import { exportThread } from '../hooks/export.js';
import { inspect, readStored, removeStored, resolveStored, store, typeOfStored } from '../hooks/upload.js';
import { BLOCKED_MESSAGE, DEAD_MESSAGE, preview } from '../hooks/preview.js';
import { readSnapshot, restore as restoreSnapshot, snapshot as buildSnapshot } from '../hooks/snapshot.js';
import {
  INVALID_TOKEN,
  consume as consumeToken,
  decode as decodeToken,
  issue as issueToken,
  resetLink,
} from '../security/jwt.js';
import { attachment as sendAttachment, redirect, text } from './response.js';
import * as validator from '../security/validator.js';
import { Mailer } from '../mail/mailer.js';
import { addFlash } from './flash.js';
import { notFound, post, requireAdmin, requireLogin, view } from './controller.js';
import { intParam } from './router.js';
import { get } from '../config/env.js';

const UNSUPPORTED_UPLOAD = 'Unsupported file type. Allowed: image/png, image/jpeg, image/gif, image/webp.';

// ------------------------------------------------------------------- avatar

/** POST /profile/avatar — multipart file part `avatar`. */
export async function avatarUpload(ctx) {
  requireLogin(ctx);
  const file = ctx.req.files.avatar;

  if (file === undefined || file.buffer === undefined || file.buffer.length === 0) {
    addFlash(ctx.session, 'error', 'Choose a file first.');
    redirect(ctx.res, '/profile');
    return;
  }

  const checked = inspect(file);
  if (!checked.ok) {
    // The size cap has already been applied by the parser (400 `File is too
    // large`), so anything reaching here is a type decision.
    renderPlainError(ctx, 400, UNSUPPORTED_UPLOAD);
    return;
  }

  const filename = store(file, checked.type);
  const previous = String(ctx.user.avatar_path ?? '');
  if (previous !== '') removeStored(previous);

  await users.setAvatarPath(Number(ctx.user.id), filename);
  addFlash(ctx.session, 'success', 'Avatar updated.');
  redirect(ctx.res, '/profile');
}

/** GET /avatar/:id — the stored image for a user, served by the app. */
export async function avatarShow(ctx, params) {
  const user = await users.findById(intParam(params, 'id'));
  if (user === null || user.avatar_path === null || String(user.avatar_path) === '') notFound(ctx);

  serveStored(ctx, String(user.avatar_path));
}

/** GET /attachment?file= — one stored upload, addressed by its generated name. */
export async function attachment(ctx) {
  requireLogin(ctx);
  serveStored(ctx, String(ctx.req.query.file ?? ''));
}

function serveStored(ctx, name) {
  const path = resolveStored(name);
  const type = typeOfStored(name);
  if (path === null || type === null) notFound(ctx);

  const body = readStored(name);
  if (body === null) notFound(ctx);

  // Content-Type comes from the allowlist entry, never from the client, and the
  // name never comes from the request beyond matching the generated shape.
  sendAttachment(ctx.res, body, { contentType: type.mime, filename: String(name), inline: true });
}

/*
 * A hook failure is a short plain-text page: the docs/02 failure contract pins
 * the message, and an error view would add markup that exploit tests would have
 * to see through.
 */
function renderPlainError(ctx, status, message) {
  text(ctx.res, `${status}\n\n${message}\n`, status);
}

// ------------------------------------------------------------------ preview

/** POST /preview — the link card (docs/03 C-SSRF-1). */
export async function previewLink(ctx) {
  requireLogin(ctx);
  const target = post(ctx, 'url') ?? '';

  const result = await preview(target);

  if (!result.ok && result.message === BLOCKED_MESSAGE) {
    renderPlainError(ctx, 400, BLOCKED_MESSAGE);
    return;
  }

  view(ctx, 'preview', {
    title: 'Link preview',
    url: target,
    card: result.ok ? result : { title: '', description: DEAD_MESSAGE },
  });
}

// -------------------------------------------------------------- xml exchange

/** GET /board/:id/export.xml */
export async function boardExport(ctx, params) {
  const board = await accessibleBoard(ctx, params);
  const xml = await exportBoard(Number(board.id));
  if (xml === null) notFound(ctx);

  sendAttachment(ctx.res, xml, { contentType: 'application/xml; charset=utf-8', filename: `board-${board.id}.xml` });
}

/** POST /board/:id/import — the envelope this app exported. */
export async function boardImport(ctx, params) {
  const board = await accessibleBoard(ctx, params);

  const uploaded = ctx.req.files.xml;
  const inline = post(ctx, 'xml');
  const payload = uploaded?.buffer ?? (inline === null || inline === '' ? null : inline);

  if (payload === null) {
    renderPlainError(ctx, 400, 'That file could not be imported.');
    return;
  }

  const parsed = importBoard(payload, Number(board.id));
  if (!parsed.ok) {
    renderPlainError(ctx, 400, parsed.message);
    return;
  }

  let threads = 0;
  let replies = 0;
  let skipped = 0;
  for (const thread of parsed.threads) {
    // Imported text goes through the same validator as a form post; the renderer
    // is applied at display time, exactly as for a typed message (C-XSS-1).
    const created = await postsRepo.createThread(Number(board.id), Number(ctx.user.id), thread.title, thread.body);
    if (created.postId === null) {
      skipped += 1;
      continue;
    }
    threads += 1;
    for (const body of thread.replies) {
      const reply = await postsRepo.createReply(created.postId, Number(ctx.user.id), body);
      if (reply.postId !== null) replies += 1;
    }
  }

  addFlash(
    ctx.session,
    threads > 0 ? 'success' : 'error',
    `Imported ${threads} thread(s) and ${replies} replie(s).${skipped > 0 ? ` ${skipped} skipped.` : ''}`,
  );
  redirect(ctx.res, `/board/${board.id}`);
}

async function accessibleBoard(ctx, params) {
  requireLogin(ctx);
  const board = await boards.find(intParam(params, 'id'));
  if (board === null || !(await boards.userCanAccess(ctx.user, board))) notFound(ctx);
  return board;
}

// --------------------------------------------------------------- directory

/** GET /directory?q=&role= */
export async function directory(ctx) {
  requireLogin(ctx);
  const q = String(ctx.req.query.q ?? '');
  const role = String(ctx.req.query.role ?? '');

  let rows = [];
  let error = null;
  try {
    rows = await directoryList(q, role);
  } catch (problem) {
    error = problem.message;
  }

  view(ctx, 'directory', { title: 'Staff directory', people: rows, q, role, filter_error: error });
}

/** POST /directory/search — the saved XPath search over the same rows. */
export async function directorySearch(ctx) {
  requireLogin(ctx);
  const q = post(ctx, 'q') ?? '';

  let result = null;
  let error = null;
  try {
    const rows = await directoryList('', '');
    result = xpathSearch(rows, q);
  } catch (problem) {
    error = problem.message;
  }

  view(ctx, 'directory', {
    title: 'Staff directory',
    people: result?.users ?? [],
    q,
    role: '',
    expression: result?.expression ?? null,
    filter_error: error,
  });
}

// ---------------------------------------------------------------- snapshot

/** GET /admin/boards/:id/snapshot.json */
export async function boardSnapshot(ctx, params) {
  requireAdmin(ctx);
  const snap = await buildSnapshot(intParam(params, 'id'));
  if (snap === null) notFound(ctx);

  // Downloaded as a file: the same bytes as `json()`, with a name that makes the
  // round trip back into the restore form obvious.
  sendAttachment(ctx.res, JSON.stringify(snap, null, 2), {
    contentType: 'application/json',
    filename: `board-${snap.board_id}-snapshot.json`,
  });
}

/** POST /admin/boards/:id/restore — a validated snapshot, in one transaction. */
export async function boardRestore(ctx, params) {
  requireAdmin(ctx);
  const board = await boards.find(intParam(params, 'id'));
  if (board === null) notFound(ctx);

  const uploaded = ctx.req.files.snapshot;
  const inline = post(ctx, 'snapshot');
  const payload = uploaded?.buffer?.toString('utf8') ?? inline;

  const read = readSnapshot(payload, Number(board.id));
  if (!read.ok) {
    renderPlainError(ctx, read.status, read.message);
    return;
  }

  const applied = await restoreSnapshot(Number(board.id), read.snapshot);
  addFlash(ctx.session, 'success', `Snapshot restored: ${applied.posts} post(s), ${applied.votes} vote(s).`);
  redirect(ctx.res, `/admin/boards/${board.id}`);
}

// ------------------------------------------------------------------ export

/** GET /thread/:id/export?format=md|txt */
export async function threadExport(ctx, params) {
  requireLogin(ctx);
  const thread = await postsRepo.getThread(intParam(params, 'id'));
  if (thread === null) notFound(ctx);

  const board = await boards.find(Number(thread.board_id));
  if (board === null || !(await boards.userCanAccess(ctx.user, board))) notFound(ctx);

  const result = exportThread(thread, await postsRepo.listReplies(Number(thread.id)), String(ctx.req.query.format ?? 'txt'));
  if (!result.ok) {
    renderPlainError(ctx, 400, result.message);
    return;
  }

  sendAttachment(ctx.res, result.body, { contentType: result.contentType, filename: result.filename });
}

// ------------------------------------------------- password reset by e-mail

/** GET /forgot-password */
export async function forgotPasswordForm(ctx) {
  view(ctx, 'forgot_password', { title: 'Reset your password' });
}

/** POST /forgot-password — the same answer for a known and an unknown address. */
export async function forgotPassword(ctx) {
  const address = String(ctx.req.fields.email ?? '').trim().toLowerCase();
  const user = address === '' ? null : await users.findByEmail(address);

  if (user !== null) {
    const { token } = issueToken({ sub: String(user.id), purpose: 'password_reset' });
    await new Mailer().send(
      String(user.email),
      `${get('APP_NAME', 'The Board')} password reset`,
      `Someone asked to reset the password for ${user.email}.\n\n` +
        `Open this link to choose a new one (it works once, for 15 minutes):\n${resetLink(token)}\n\n` +
        'If you did not ask for this, nothing has changed and you can ignore this message.\n',
    );
  }

  view(ctx, 'forgot_password', {
    title: 'Reset your password',
    sent: 'If that address has an account, a reset link is on its way.',
  });
}

/** GET /reset-password?token= */
export async function resetPasswordForm(ctx) {
  const token = String(ctx.req.query.token ?? '');
  view(ctx, 'reset_password', { title: 'Choose a new password', token });
}

/** POST /reset-password — single-use token, then the new password. */
export async function resetPassword(ctx) {
  const token = String(ctx.req.fields.token ?? '');

  // Checked first, spent last: a token is only burned by an attempt that could
  // actually change a password, so a mistyped new password does not waste the
  // single use. `decode` has no side effects — signature, algorithm, issuer,
  // expiry and purpose only.
  const checked = decodeToken(token, 'password_reset');
  if (!checked.ok) {
    // No account enumeration, and the same answer for expired, used, forged.
    view(ctx, 'reset_password', {
      title: 'Choose a new password',
      token,
      error: INVALID_TOKEN,
      status: 200,
    });
    return;
  }

  const newPassword = String(ctx.req.fields.password ?? '');
  const confirm = String(ctx.req.fields.password_confirm ?? '');
  const errors = [...validator.password(newPassword), ...(newPassword === confirm ? [] : ['The two passwords do not match.'])];

  if (errors.length > 0) {
    for (const message of errors) addFlash(ctx.session, 'error', message);
    redirect(ctx.res, `/reset-password?token=${encodeURIComponent(token)}`);
    return;
  }

  // The claim is spent here; a race or a replay loses at this point and gets the
  // same answer as any other invalid token.
  const spent = await consumeToken(token, 'password_reset');
  if (!spent.ok) {
    view(ctx, 'reset_password', { title: 'Choose a new password', token, error: INVALID_TOKEN, status: 200 });
    return;
  }

  await users.updatePassword(Number(checked.payload.sub), newPassword);
  addFlash(ctx.session, 'success', 'Password updated. Sign in with your new password.');
  redirect(ctx.res, '/login');
}
