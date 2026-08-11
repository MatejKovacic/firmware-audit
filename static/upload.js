(() => {
  const form = document.querySelector('[data-upload-form]');
  const result = document.querySelector('[data-upload-result]');
  if (!form || !result) return;

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = form.querySelector('button[type="submit"]');
    if (!button || button.disabled) return;

    const original = button.textContent;
    button.disabled = true;
    button.textContent = 'Uploading…';
    result.textContent = '';
    result.className = 'upload-result';

    try {
      const response = await fetch(form.action, {
        method: 'POST',
        body: new FormData(form),
        credentials: 'same-origin',
        headers: {'Accept': 'application/json'},
      });
      let payload;
      try {
        payload = await response.json();
      } catch (_) {
        payload = {status: 'error', message: `Upload failed (HTTP ${response.status}).`};
      }
      if (!response.ok || payload.status !== 'ok') {
        throw new Error(payload.message || `Upload failed (HTTP ${response.status}).`);
      }
      result.textContent = payload.message || 'Report uploaded successfully.';
      result.classList.add('upload-result-success');
    } catch (error) {
      result.textContent = error instanceof Error ? error.message : 'Upload failed.';
      result.classList.add('upload-result-error');
    } finally {
      button.disabled = false;
      button.textContent = original;
    }
  });
})();
