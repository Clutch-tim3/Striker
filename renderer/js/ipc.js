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
    execCommand: async (cmd, options = {}) => {
      console.log('[IPC mock] execCommand:', cmd);
      return {
        stdout: `[Mock] Would execute: ${cmd}\n`,
        stderr: '',
      };
    },
  };
}
