// Thread view and replies — port of src/Http/ThreadController.php
// (docs/02 B18, B20, B21).

import { Halt, csrf, notFound, post, requireLogin, view } from './controller.js';
import { redirect } from './response.js';
import { addFlash } from './flash.js';
import { intParam } from './router.js';
import * as boards from '../repositories/board.repository.js';
import * as posts0 from '../repositories/post.repository.js';

/** Thread detail: the original post plus its replies. */
export async function show(ctx, params) {
  const user = requireLogin(ctx);
  const thread = await posts0.getThread(intParam(params, 'id'));
  if (thread === null) notFound(ctx);

  const board = await boards.find(Number(thread.board_id));
  if (board === null || !(await boards.userCanAccess(user, board))) notFound(ctx);

  const replies = await posts0.listReplies(Number(thread.id));

  view(ctx, 'thread', {
    title: String(thread.title),
    thread,
    board,
    replies,
    old_body: ctx.session.data.old_reply_body ?? '',
  });

  ctx.session.data.old_reply_body = null;
}

/** Reply to a thread. */
export async function reply(ctx, params) {
  csrf(ctx);
  const user = requireLogin(ctx);
  const thread = await posts0.getThread(intParam(params, 'id'));
  if (thread === null) notFound(ctx);

  const board = await boards.find(Number(thread.board_id));
  if (board === null || !(await boards.userCanAccess(user, board))) notFound(ctx);

  const body = post(ctx, 'body') ?? '';
  const { postId, errors } = await posts0.createReply(Number(thread.id), Number(user.id), body);
  if (postId === null) {
    for (const message of errors) addFlash(ctx.session, 'error', message);
    ctx.session.data.old_reply_body = body;
  } else {
    addFlash(ctx.session, 'success', 'Reply posted.');
  }

  redirect(ctx.res, `/thread/${thread.id}`);
  throw new Halt();
}
