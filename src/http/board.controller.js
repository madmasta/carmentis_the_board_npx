// Board pages — port of src/Http/BoardController.php (docs/02 B16, B17).
//
// The access check is C-ACL-1: the board row is loaded, `userCanAccess` decides,
// and a denial is a 404 — never a 403, so a restricted board is indistinguishable
// from one that does not exist.

import { Halt, csrf, forbidden, notFound, posts, requireLogin, view } from './controller.js';
import { redirect } from './response.js';
import { addFlash } from './flash.js';
import { intParam } from './router.js';
import * as boards from '../repositories/board.repository.js';
import * as posts0 from '../repositories/post.repository.js';
import * as validator from '../security/validator.js';

/** Board page: thread list + the new-thread form. */
export async function show(ctx, params) {
  const user = requireLogin(ctx);
  const board = await boards.find(intParam(params, 'id'));
  if (board === null || !(await boards.userCanAccess(user, board))) notFound(ctx);

  const page = intParamQuery(ctx, 'page', 1);
  const threads = await posts0.listThreads(Number(board.id), page);
  const total = await posts0.countThreads(Number(board.id));
  const pages = Math.max(1, Math.ceil(total / posts0.THREADS_PER_PAGE));

  view(ctx, 'board', {
    title: String(board.name),
    board,
    threads,
    page,
    pages,
    old_title: ctx.session.data.old_thread_title ?? '',
    old_body: ctx.session.data.old_thread_body ?? '',
  });

  ctx.session.data.old_thread_title = null;
  ctx.session.data.old_thread_body = null;
}

/** Create a new thread in a board. */
export async function createThread(ctx, params) {
  csrf(ctx);
  const user = requireLogin(ctx);
  const board = await boards.find(intParam(params, 'id'));
  if (board === null || !(await boards.userCanAccess(user, board))) notFound(ctx);

  const in_ = posts(ctx, ['title', 'body']);
  const errors = [...validator.postTitle(in_.title), ...validator.messageBody(in_.body)];
  if (errors.length > 0) {
    for (const message of errors) addFlash(ctx.session, 'error', message);
    ctx.session.data.old_thread_title = in_.title;
    ctx.session.data.old_thread_body = in_.body;
    redirect(ctx.res, `/board/${board.id}`);
    throw new Halt();
  }

  const { postId } = await posts0.createThread(Number(board.id), Number(user.id), in_.title, in_.body);
  addFlash(ctx.session, 'success', 'Thread posted.');
  redirect(ctx.res, `/thread/${postId}`);
  throw new Halt();
}

/** `?page=N` — digits only, anything else is page 1. */
function intParamQuery(ctx, name, fallback) {
  const raw = ctx.req.query?.[name];
  if (typeof raw !== 'string' || !/^\d+$/.test(raw)) return fallback;
  return Math.max(1, Number(raw));
}
