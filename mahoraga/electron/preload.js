const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('mahoraga', {
  send: (command, payload = {}) =>
    ipcRenderer.invoke('send-to-python', { command, payload }),

  onEvent: (callback) =>
    ipcRenderer.on('python-event', (_, data) => callback(data)),

  offEvent: (callback) =>
    ipcRenderer.removeListener('python-event', callback),

  platform: process.platform,
  version: process.env.npm_package_version,
});
