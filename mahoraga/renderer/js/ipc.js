// Thin wrapper — provides fallback when running outside Electron (e.g. browser preview)
if (typeof window.mahoraga === 'undefined') {
  window.mahoraga = {
    send: (command, payload = {}) => {
      console.log('[IPC mock] send', command, payload);
      return Promise.resolve({ ok: true });
    },
    onEvent: (cb) => {
      window._mahoraga_callbacks = window._mahoraga_callbacks || [];
      window._mahoraga_callbacks.push(cb);
    },
    offEvent: () => {},
    platform: 'darwin',
    version: '1.0.0',
  };

  // In dev/browser mode, simulate occasional threat events for UI testing
  if (window.location.protocol === 'file:' && !window.__electron__) {
    setTimeout(() => {
      (window._mahoraga_callbacks || []).forEach(cb => cb({
        type: 'MONITORING_STARTED', data: { status: 'active' }
      }));
    }, 500);
  }
}
