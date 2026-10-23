// Vitest configuration (docs/04 section 1).
//
// The suite talks to a real MariaDB, so:
//   * files run one at a time — every suite shares the one test database and
//     `test/helpers/db.mjs` truncates between suites;
//   * `globalSetup` performs the PHP-bootstrap equivalent (drop + create +
//     schema) exactly once per run;
//   * no mocks of the app itself: suites import `src/server.js` and drive it
//     with supertest, the same code `npm start` runs.

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.mjs'],
    globalSetup: ['./test/helpers/global-setup.mjs'],
    setupFiles: ['./test/helpers/setup.mjs'],
    fileParallelism: false,
    sequence: { hooks: 'stack' },
    testTimeout: 30_000,
    hookTimeout: 120_000,
  },
});
