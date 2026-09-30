'use strict';

/* Progressive enhancement only: every feature here also works with JS off. */
(() => {
  const MAX_BYTES = Number(document.body.dataset.maxBytes || 0);

  const editor = document.querySelector('.editor');
  const counter = document.querySelector('[data-counter]');
  const privateBox = document.querySelector('input[name="private"]');
  const pwField = document.querySelector('.pw');

  if (editor && counter) {
    const update = () => {
      const bytes = new TextEncoder().encode(editor.value).length;
      counter.textContent = `${bytes.toLocaleString()} B${MAX_BYTES ? ` / ${(MAX_BYTES / 1024).toFixed(0)} KiB` : ''}`;
      counter.classList.toggle('over', MAX_BYTES > 0 && bytes > MAX_BYTES);
    };
    editor.addEventListener('input', update);
    update();
  }

  if (privateBox && pwField) {
    const sync = () => pwField.classList.toggle('on', privateBox.checked);
    privateBox.addEventListener('change', sync);
    sync();
  }

  // Tab inserts two spaces instead of leaving the field, but Escape-then-Tab
  // still moves focus so the editor stays keyboard navigable.
  if (editor) {
    editor.addEventListener('keydown', (event) => {
      if (event.key !== 'Tab' || event.ctrlKey || event.metaKey || event.altKey) return;
      event.preventDefault();
      const { selectionStart: start, selectionEnd: end, value } = editor;
      editor.value = `${value.slice(0, start)}  ${value.slice(end)}`;
      editor.selectionStart = editor.selectionEnd = start + 2;
      editor.dispatchEvent(new Event('input'));
    });
  }

  for (const button of document.querySelectorAll('[data-copy]')) {
    button.addEventListener('click', async () => {
      const original = button.textContent;
      try {
        await navigator.clipboard.writeText(button.dataset.copy);
        button.textContent = 'copied';
      } catch {
        button.textContent = 'press ctrl+c';
      }
      setTimeout(() => { button.textContent = original; }, 1500);
    });
  }

  /* ------------------------------------------------- proof of work (signup) */

  const pow = document.querySelector('[data-pow]');
  if (!pow) return;

  const fill = pow.querySelector('[data-pow-fill]');
  const status = pow.querySelector('[data-pow-status]');
  const nonceField = pow.querySelector('[data-pow-nonce]');
  const form = pow.closest('form');
  const submit = form?.querySelector('button[type="submit"]');
  const bits = Number(pow.dataset.bits) || 0;
  const budget = Number(pow.dataset.budget) || 0;

  const setStatus = (text, kind) => {
    if (!status) return;
    status.textContent = text;
    status.classList.toggle('done', kind === 'done');
    status.classList.toggle('failed', kind === 'failed');
  };

  // Expected total is 2^bits, so remaining work halves as attempts rise. The
  // estimate is crude and only drives the bar, never the decision.
  const expected = Math.pow(2, bits);
  const showProgress = (attempts) => {
    if (!fill) return;
    const done = Math.min(99, (attempts / expected) * 100);
    fill.style.width = `${done.toFixed(1)}%`;
  };

  const fail = (message) => {
    setStatus(message, 'failed');
    pow.classList.add('pow-failed');
    // No nonce is submitted, so the server falls back to the honeypot and the
    // signup rate limit rather than locking the visitor out.
    if (submit) submit.disabled = false;
  };

  if (!window.Worker || typeof crypto?.getRandomValues !== 'function') {
    fail('Could not start the browser check. Reload, or try another browser.');
    return;
  }

  setStatus('checking your browser is real…');
  if (submit) submit.disabled = true;

  let worker;
  try {
    worker = new Worker('/static/pow-worker.js');
  } catch {
    fail('Could not start the browser check. Reload, or try another browser.');
    return;
  }

  const id = Math.floor(Math.random() * 1e9);

  const stop = () => {
    worker.terminate();
    if (submit) submit.disabled = false;
  };

  // Hard stop independent of the worker's own budget, so a wedged worker
  // cannot leave the form permanently disabled.
  const guard = setTimeout(() => {
    fail('That took too long. Try again, or use another browser.');
    stop();
  }, budget + 5000);

  worker.onmessage = (event) => {
    const message = event.data;
    if (!message || message.id !== id) return;

    if (message.type === 'progress') {
      showProgress(message.attempts);
      return;
    }

    if (message.type === 'done') {
      clearTimeout(guard);
      if (message.timedOut || message.nonce === null) {
        fail('That took too long. Try again, or use another browser.');
      } else {
        nonceField.value = message.nonce;
        pow.classList.add('pow-ok');
        if (fill) fill.style.width = '100%';
        setStatus(`verified in ${(message.ms / 1000).toFixed(1)}s`, 'done');
      }
      stop();
      return;
    }

    if (message.type === 'error') {
      clearTimeout(guard);
      fail('Could not start the browser check. Reload, or try another browser.');
      stop();
    }
  };

  worker.onerror = () => {
    clearTimeout(guard);
    fail('Could not start the browser check. Reload, or try another browser.');
    stop();
  };

  worker.postMessage({
    id,
    challenge: pow.dataset.challenge,
    bits,
    budgetMs: budget,
  });
})();