const { contextBridge, ipcRenderer } = require('electron');
const { exec } = require('child_process');

try {
  console.log('DEBUG: preload loaded');

  contextBridge.exposeInMainWorld('mahoraga', {
    send: (command, payload = {}) => {
      console.log('DEBUG preload: send called with:', command, payload);
      try {
        return ipcRenderer.invoke('send-to-python', { command, payload });
      } catch (e) {
        console.error('DEBUG preload: send error:', e);
      }
    },
    onEvent: (callback) =>
      ipcRenderer.on('python-event', (_, data) => callback(data)),

    offEvent: (callback) =>
      ipcRenderer.removeListener('python-event', callback),

    platform: process.platform,
    version: process.env.npm_package_version,

    execCommand: (cmd, options = {}) => {
      return new Promise((resolve, reject) => {
        const timeout = options.timeout || 30000;
        const cwd = options.cwd || process.env.HOME || '/tmp';

        exec(cmd, { timeout, cwd, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
          if (error) {
            if (error.killed) {
              reject(new Error('Command timed out'));
            } else {
              reject(error);
            }
          } else {
            resolve({ stdout, stderr });
          }
        });
      });
    },
  });

  console.log('DEBUG: mahoraga exposed');
} catch (e) {
  console.error('DEBUG: preload error:', e);
}
