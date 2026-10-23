// Entry point — the equivalent of public/index.php (docs/01 section 1).

import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { existsSync } from 'node:fs';

import { get, int, load } from './config/env.js';
import { root } from './db/admin.js';
import { createRequestHandler } from './http/server.js';
import { routes } from './routes.js';
import { close } from './db/connection.js';
import { error as logError, info as logInfo } from './lib/log.js';

export function loadEnv() {
  const envFile = join(root(), '.env');
  if (!existsSync(envFile)) {
    throw new Error(`no .env in ${root()} — copy .env.example to .env and try again`);
  }
  load(envFile);
}

export function createApp() {
  return createServer(createRequestHandler(routes));
}

export function start() {
  loadEnv();
  const host = get('HOST', '127.0.0.1');
  const port = int('PORT', 8088);
  const server = createApp();

  server.listen(port, host, () => {
    logInfo('start', `listening on http://${host}:${port} (db ${get('DB_NAME')})`);
    process.stdout.write(`The Board (node) listening on http://${host}:${port}\n`);
  });

  const shutdown = (signal) => {
    logInfo('stop', `received ${signal}`);
    server.close(() => {
      close().finally(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  return server;
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  try {
    start();
  } catch (error) {
    logError(error.message);
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}
