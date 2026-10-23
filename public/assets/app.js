/* Progressive enhancement only. CSP forbids inline script (C-XSS-3), so this is
   the one external file, and every DOM write below uses inert sinks — the
   xss_dom branch is what turns renderQueryChip() into an HTML sink. */

'use strict';

/** Confirm before submitting a destructive form. */
function bindConfirmForms() {
  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm || 'Are you sure?')) {
        event.preventDefault();
      }
    });
  });
}

/** Disable a vote button once it has been submitted, so one click = one POST. */
function bindVoteButtons() {
  document.querySelectorAll('form[data-vote]').forEach((form) => {
    form.addEventListener('submit', () => {
      const button = form.querySelector('button[type=submit]');
      if (button) button.disabled = true;
    });
  });
}

/**
 * Staff directory: echo the current search term back into the chip.
 * `textContent` is the inert sink; do not change it to innerHTML.
 */
function renderQueryChip() {
  const chip = document.querySelector('[data-q-chip]');
  if (!chip) return;
  const term = new URLSearchParams(window.location.search).get('q') ?? '';
  chip.textContent = term;
}

function boot() {
  bindConfirmForms();
  bindVoteButtons();
  renderQueryChip();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
