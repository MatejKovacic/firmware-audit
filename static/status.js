(() => {
  const box = document.getElementById('collection-status');
  const normalTitle = document.title;
  if (!box) return;
  const url = box.dataset.statusUrl;
  const label = document.getElementById('collection-status-label');
  const area = document.getElementById('collection-status-area');
  const progress = document.getElementById('collection-status-progress');
  const bar = document.getElementById('collection-status-bar');
  const message = document.getElementById('collection-status-message');
  const log = document.getElementById('collection-status-log');

  function text(value) { return value == null ? '' : String(value); }
  function render(data) {
    const state = text(data.state || 'idle');
    box.className = `collection-status state-${state}`;
    if (state === 'running') label.textContent = 'Scanning security areas…';
    else if (state === 'completed') label.textContent = 'Last scan completed';
    else if (state === 'failed') label.textContent = 'Last scan stopped';
    else label.textContent = 'Scanner status';
    area.textContent = text(data.current_area || data.message || '');
    const pct = Math.max(0, Math.min(100, Number(data.progress_percent || 0)));
    progress.textContent = state === 'running' ? `${pct}%` : '';
    bar.style.width = `${pct}%`;
    message.textContent = text(data.message || '');
    log.replaceChildren();
    for (const entry of (Array.isArray(data.log) ? data.log : [])) {
      const li = document.createElement('li');
      const time = document.createElement('time');
      const parsed = new Date(entry.at);
      time.textContent = Number.isNaN(parsed.getTime()) ? text(entry.at) : parsed.toLocaleTimeString();
      const strong = document.createElement('strong');
      strong.textContent = text(entry.area);
      const span = document.createElement('span');
      span.textContent = text(entry.message);
      li.append(time, strong, span);
      log.appendChild(li);
    }
    document.title = state === 'running' ? 'Scanning… · Firmware Audit' : normalTitle;
  }

  async function poll() {
    try {
      const response = await fetch(url, {cache: 'no-store', credentials: 'same-origin'});
      if (response.ok) render(await response.json());
    } catch (_) {
      // The current snapshot remains usable if the transient status channel is unavailable.
    }
  }
  poll();
  window.setInterval(poll, 1500);
})();
