// Post editing and moderation — port of src/Http/PostController.php
// (docs/02 B22, B23, docs/03 C-ACL-3).

import { BODY_MAX } from '../security/validator.js';
import { Halt, csrf, forbidden, notFound, post, requireAdmin, requireLogin, view } from './controller.js';
import { redirect } from './response.js';
import { addFlash } from './flash.js';
import { internalReferer } from './response.js';
import { intParam } from './router.js';
import * as posts0 from '../repositories/post.repository.js';

function targetFor(postRow) {
  return postRow.parent_id !== null ? `/thread/${Number(postRow.parent_id)}` : `/thread/${postRow.id}`;
}

/** Edit form: an author edits their own post, an admin edits anything. */
export async function editForm(ctx, params) {
  const user = requireLogin(ctx);
  const postRow = await posts0.find(intParam(params, 'id'));
  if (postRow === null) notFound(ctx);

  const isAdmin = user.role === 'admin';
  if (!isAdmin && Number(postRow.author_id) !== Number(user.id)) forbidden(ctx, 'You can only edit your own posts.');

  view(ctx, 'edit_post', { title: 'Edit message', post: postRow });
}

export async function editSubmit(ctx, params) {
  csrf(ctx);
  const user = requireLogin(ctx);
  const postRow = await posts0.find(intParam(params, 'id'));
  if (postRow === null) notFound(ctx);

  const isAdmin = user.role === 'admin';
  if (!isAdmin && Number(postRow.author_id) !== Number(user.id)) forbidden(ctx, 'You can only edit your own posts.');

  const body = post(ctx, 'body') ?? '';
  const saved = await posts0.editPost(Number(postRow.id), Number(user.id), isAdmin, body);
  if (!saved) {
    addFlash(
      ctx.session,
      'error',
      `Could not save the edit (message must not be empty and at most ${BODY_MAX} characters).`,
    );
    redirect(ctx.res, `/post/${postRow.id}/edit`);
    throw new Halt();
  }

  addFlash(ctx.session, 'success', 'Message updated.');
  redirect(ctx.res, targetFor(postRow));
  throw new Halt();
}

/** Soft delete — admins only. A second delete changes nothing and still flashes success (B23). */
export async function remove(ctx, params) {
  csrf(ctx);
  const admin = requireAdmin(ctx);
  const postRow = await posts0.find(intParam(params, 'id'));
  if (postRow === null) notFound(ctx);

  await posts0.deletePost(Number(postRow.id), Number(admin.id));
  addFlash(ctx.session, 'success', 'Message deleted.');
  redirect(ctx.res, internalReferer(ctx.req.headers.referer) ?? '/');
  throw new Halt();
}

export { targetFor };
