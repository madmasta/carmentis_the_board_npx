// Home page — port of src/Http/PageController.php (docs/02 B16).

import { view } from './controller.js';
import * as boards from '../repositories/board.repository.js';

export async function home(ctx) {
  const visible = await boards.listForUser(ctx.user);
  view(ctx, 'home', { title: 'Boards', boards: visible });
}
