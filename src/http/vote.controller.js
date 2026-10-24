// Voting — port of src/Http/VoteController.php (docs/02 B24, B25).

import { Halt, csrf, forbidden, notFound, requireLogin } from './controller.js';
import { internalReferer, redirect } from './response.js';
import { renderError } from '../views.js';
import * as boards from '../repositories/board.repository.js';
import * as posts0 from '../repositories/post.repository.js';
import * as votes from '../repositories/vote.repository.js';

/** POST /vote with post_id and value (1 or -1). Voting twice removes the vote. */
export async function vote(ctx) {
  csrf(ctx);
  const user = requireLogin(ctx);

  // Per-route DTO cast (C-ASSIGN-1): an explicit numeric cast plus a range check,
  // never the raw field.
  const postId = Number.parseInt(String(ctx.req.fields.post_id ?? ''), 10);
  const value = Number.parseInt(String(ctx.req.fields.value ?? ''), 10);
  if (!Number.isInteger(postId) || postId <= 0 || (value !== 1 && value !== -1)) {
    renderError(ctx.res, 400, 'Invalid vote.');
    throw new Halt();
  }

  const postRow = await posts0.find(postId);
  if (postRow === null) notFound(ctx);

  const board = await boards.find(Number(postRow.board_id));
  if (board === null || !(await boards.userCanAccess(user, board))) {
    forbidden(ctx, 'You do not have access to this board.');
  }

  await votes.vote(Number(postRow.id), Number(user.id), value);

  // Return to the page the vote came from. PHP compared the absolute referer to
  // APP_URL; the port converts a same-origin referer to its path because
  // C-REDIRECT-1's safeRedirectLocation rejects absolute targets.
  const back = internalReferer(ctx.req.headers.referer);
  if (back !== null) {
    redirect(ctx.res, back);
    throw new Halt();
  }
  redirect(ctx.res, postRow.parent_id !== null ? `/thread/${Number(postRow.parent_id)}` : `/thread/${postRow.id}`);
  throw new Halt();
}
