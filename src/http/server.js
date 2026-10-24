// The request pipeline — the Node equivalent of public/index.php
// (docs/01 section 1). Order is part of the security model:
//
//   security headers → parsing → host check → static allowlist → session start
//   (with the ban kill) → route match → CSRF → guard → handler → error path
//
// Static serving is an allowlist of two named files; there is no directory
// handler and no listing anywhere (C-INFO-2). The request log records the
// matched route template, never the raw target (C-INFO-3).

import { createReadStream, statSync } from 'node:fs';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';

import { bool, get } from '../config/env.js';
import { root } from '../db/admin.js';
import { consumeFault } from '../lib/faults.js';
import { error as logError, errorStack, info as logInfo } from '../lib/log.js';
import { start as startSession, save as saveSession } from '../session/store.js';
import { notFound, renderError } from '../views.js';
import { tryRemember } from '../auth/remember.js';
import { Halt, applyGuard, csrf as csrfCheck, loadUser, makeContext } from './controller.js';
import { applySecurityHeaders, setHeader } from './headers.js';
import { RequestError, hostIsAllowed, parse } from './request.js';
import { match } from './router.js';

/** The only URL-reachable files (docs/03 C-INFO-2). */
const STATIC_FILES = new Map([
  [
    '/assets/style.css',
    { file: join(root(), 'public', 'assets', 'style.css'), type: 'text/css; charset=utf-8' },
  ],
  [
    '/assets/app.js',
    { file: join(root(), 'public', 'assets', 'app.js'), type: 'text/javascript; charset=utf-8' },
  ],
]);

async function serveStatic(res, path) {
  const entry = STATIC_FILES.get(path);
  if (!entry) return false;
  setHeader(res, 'Content-Type', entry.type);
  setHeader(res, 'Cache-Control', 'no-cache');
  setHeader(res, 'Content-Length', String(statSync(entry.file).size));
  await pipeline(createReadStream(entry.file), res);
  return true;
}

/** A minimal context for the remember step, before the route is known. */
function makeRememberContext(req, res, session, user) {
  return { req, res, session, user };
}

function logRequest(method, routeTemplate, statusCode, session) {
  logInfo('request', `${method} ${routeTemplate} -> ${statusCode} uid=${session?.userId ?? '-'}`);
}

export function createRequestHandler(routes) {
  return async function handle(req, res) {
    const method = req.method ?? 'GET';
    let routeTemplate = 'unmatched';
    let session = null;
    const https = req.socket?.encrypted === true;

    // Headers first, so a rejection, an error page and a 404 all carry them.
    applySecurityHeaders(res, { https });

    try {
      // The raw pathname, not the normalised `req.path`: a trailing slash must
      // not reach an allowlisted file.
      const rawPath = new URL(req.url ?? '/', 'http://localhost').pathname;

      const parsed = await parse(req);
      Object.assign(req, parsed);

      if (!hostIsAllowed(req)) {
        routeTemplate = 'host-rejected';
        renderError(res, 400, 'Unknown host.');
        logRequest(method, routeTemplate, res.statusCode, session);
        return;
      }

      if (method === 'GET' && (await serveStatic(res, rawPath))) {
        routeTemplate = 'static';
        logRequest(method, routeTemplate, res.statusCode, session);
        return;
      }

      req.https = https;
      session = await startSession(req, res);
      req.session = session;
      let user = await loadUser(session.userId);
      if (user === null) {
        // No session but a live remember token: the token is checked before any
        // identity is taken from it (docs/03 C-JWT-1).
        user = await tryRemember(makeRememberContext(req, res, session, user));
      }

      consumeFault(); // deterministic 500 probe; never armed in a normal run

      const found = match(routes, method, req.path);
      if (found === null) {
        routeTemplate = '404';
        notFound(res);
        logRequest(method, routeTemplate, res.statusCode, session);
        await saveSession(session, res, { https });
        return;
      }

      routeTemplate = found.entry.path;
      const ctx = makeContext(req, res, session, user);

      if (found.entry.csrf) csrfCheck(ctx);
      await applyGuard(ctx, found.entry.guard);
      await found.entry.handler(ctx, found.params);

      logRequest(method, routeTemplate, res.statusCode, session);
      await saveSession(session, res, { https });
    } catch (error) {
      if (error instanceof Halt) {
        // A guard already answered; still persist whatever the session holds.
        await persistSession(session, res, https);
        logRequest(method, routeTemplate, res.statusCode, session);
        return;
      }

      if (error instanceof RequestError) {
        renderError(res, error.status, error.message);
        logRequest(method, routeTemplate, res.statusCode, session);
        return;
      }

      logError(`unhandled error on ${method} ${routeTemplate}`);
      errorStack(error);
      renderError(res, 500, 'Something went wrong. The error has been logged.', {
        trace: bool('APP_DEBUG', false) ? (error?.stack ?? String(error)) : null,
      });
      logRequest(method, routeTemplate, res.statusCode, session);
    } finally {
      if (!res.writableEnded) {
        if (!res.headersSent) res.statusCode = res.statusCode || 500;
        res.end();
      }
      void get('APP_LOG_TIMING'); // reserved for the harness; never changes behaviour
    }
  };
}

async function persistSession(session, res, https) {
  if (session === null) return;
  try {
    await saveSession(session, res, { https });
  } catch {
    /* the response is already complete; the row is still written */
  }
}
