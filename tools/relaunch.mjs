#!/usr/bin/env node
// Start (or restart) the app as a detached host process — the bring-up step the
// Carmentis harness runs between branches (`[campaign.runtime].restart` in
// configs/TheBoardNode_campaign.toml).
//
//   node tools/relaunch.mjs            # stop whatever holds the port, start a new one
//   node tools/relaunch.mjs --stop     # stop only
//   node tools/relaunch.mjs --status   # is the app answering, and who owns the port
//
// The harness needs a command that *returns* with the app running and answering.
// `npm start` in the foreground would hang the harness, and a bare detached spawn
// would let the harness start Phase 1 against a server that has not bound its port
// yet — or worse, against the PREVIOUS branch's server, which is exactly what
// happens if a stale instance still owns the port: the new one dies of EADDRINUSE
// while the old one keeps answering. So the stop step works off the port owner as
// well as the recorded pid, and the health step checks that the answering process
// is the one this command started.

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync, spawn } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { get, int, load } from '../src/config/env.js';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const pidFile = join(root, 'var', 'app.pid');
const healthPath = '/health';
const isWindows = process.platform === 'win32';

load(join(root, '.env'));
const host = get('HOST', '127.0.0.1');
const port = int('PORT', 8088);

function readPid() {
  if (!existsSync(pidFile)) return null;
  const pid = Number.parseInt(readFileSync(pidFile, 'utf8').trim(), 10);
  return Number.isInteger(pid) && pid > 0 ? pid : null;
}

/** Pids holding a LISTEN socket on `port` — the authority on who is really serving. */
function listenersOn(targetPort) {
  const pids = new Set();
  try {
    if (isWindows) {
      const out = execFileSync('netstat', ['-ano', '-p', 'tcp'], { encoding: 'utf8' });
      for (const line of out.split('\n')) {
        const match = line.match(/^\s*TCP\s+\S+?:(\d+)\s+\S+\s+LISTENING\s+(\d+)/i);
        if (match && Number(match[1]) === targetPort) pids.add(Number(match[2]));
      }
    } else {
      const out = execFileSync('sh', ['-c', `ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null`], { encoding: 'utf8' });
      for (const line of out.split('\n')) {
        if (!new RegExp(`:${targetPort}\\s`).test(line)) continue;
        const pid = Number.parseInt((line.match(/pid=(\d+)/) ?? [])[1] ?? '', 10);
        if (Number.isInteger(pid)) pids.add(pid);
      }
    }
  } catch {
    /* no socket tool available — the caller falls back to the pid file */
  }
  return [...pids];
}

function alive(pid) {
  if (pid === null || !Number.isInteger(pid)) return false;
  if (listenersOn(port).includes(pid)) return true;
  try {
    if (isWindows) {
      const out = execFileSync('tasklist', ['/FI', `PID eq ${pid}`, '/NH'], { encoding: 'utf8' });
      return out.includes(String(pid));
    }
    process.kill(pid, 0); // signal 0 == "is this process mine to signal"
    return true;
  } catch {
    return false;
  }
}

function terminate(pid) {
  try {
    if (isWindows) {
      // A Node child on Windows ignores SIGTERM; ask taskkill, gently first.
      execFileSync('taskkill', ['/pid', String(pid)], { stdio: 'ignore' });
    } else {
      process.kill(pid, 'SIGTERM');
    }
    return true;
  } catch {
    return false;
  }
}

function killHard(pid) {
  try {
    if (isWindows) execFileSync('taskkill', ['/F', '/pid', String(pid)], { stdio: 'ignore' });
    else process.kill(pid, 'SIGKILL');
  } catch {
    /* losing the race to an already-exited process is fine */
  }
}

async function stopEverything(timeoutMs = 10000) {
  const recorded = readPid();
  const targets = new Set([...listenersOn(port), ...(recorded === null ? [] : [recorded])]);

  if (targets.size === 0) {
    rmSync(pidFile, { force: true });
    return { stopped: [], orphaned: false };
  }

  for (const pid of targets) terminate(pid);

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline && listenersOn(port).length > 0) {
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  for (const pid of listenersOn(port)) killHard(pid);

  rmSync(pidFile, { force: true });
  return { stopped: [...targets] };
}

/** One health probe. The timer is cleared explicitly — an unclosed timer handle plus
 *  a hard exit is what makes Node on Windows abort inside uv_async.c. */
async function healthy(timeoutMs = 1500) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`http://${host}:${port}${healthPath}`, { signal: controller.signal });
    return response.status < 500;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  const args = new Set(process.argv.slice(2));

  if (args.has('--status')) {
    const owners = listenersOn(port);
    const recorded = readPid();
    const answering = await healthy();
    console.log(
      `port ${port}: ${owners.length > 0 ? `listeners ${owners.join(',')}` : 'nothing listening'}` +
        ` · recorded pid ${recorded ?? 'none'} · ${healthPath} ${answering ? 'answers' : 'silent'}`,
    );
    return answering && owners.length > 0 ? 0 : 1;
  }

  const { stopped } = await stopEverything();
  console.log(stopped.length > 0 ? `stopped: ${stopped.join(', ')}` : 'nothing was listening on the port');

  if (args.has('--stop')) return 0;

  if (listenersOn(port).length > 0) {
    console.error(`relaunch: port ${port} is still held after the stop step — refusing to start a second server`);
    return 1;
  }

  mkdirSync(join(root, 'var'), { recursive: true });
  const child = spawn(process.execPath, [join(root, 'src', 'server.js')], {
    cwd: root,
    env: { ...process.env },
    detached: true,
    stdio: 'ignore',
  });
  child.unref();
  if (!Number.isInteger(child.pid)) {
    console.error('relaunch: the server process could not be started');
    return 1;
  }
  writeFileSync(pidFile, `${child.pid}\n`);

  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const owners = listenersOn(port);
    if (owners.includes(child.pid) && (await healthy())) {
      console.log(`pid ${child.pid} listening on ${host}:${port} and answering ${healthPath}`);
      return 0;
    }
    if (!alive(child.pid)) {
      console.error(
        `relaunch: pid ${child.pid} exited. If the port was taken, the answer is in the previous lines; ` +
          'otherwise run `npm start` in the foreground to see the error.',
      );
      rmSync(pidFile, { force: true });
      return 1;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  console.error(`relaunch: pid ${child.pid} did not come up on ${host}:${port} within 30s`);
  return 1;
}

// exitCode rather than exit(): the detached child and the health timers are still
// winding down, and a hard exit in that window aborts the runtime on Windows.
process.exitCode = await main();
