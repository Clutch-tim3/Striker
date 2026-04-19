module.exports = function registerHandlers(ipcMain, sendToPython) {
  ipcMain.handle('start-monitoring', async () => {
    sendToPython({ command: 'START_MONITORING' });
  });

  ipcMain.handle('stop-monitoring', async () => {
    sendToPython({ command: 'STOP_MONITORING' });
  });

  ipcMain.handle('get-archive', async (_, filters) => {
    sendToPython({ command: 'GET_ARCHIVE', payload: filters });
  });

  ipcMain.handle('quarantine-file', async (_, filePath) => {
    sendToPython({ command: 'QUARANTINE', payload: { path: filePath } });
  });

  ipcMain.handle('kill-process', async (_, pid) => {
    sendToPython({ command: 'KILL_PROCESS', payload: { pid } });
  });

  ipcMain.handle('isolate-network', async () => {
    sendToPython({ command: 'ISOLATE_NETWORK' });
  });

  ipcMain.handle('get-config', async () => {
    sendToPython({ command: 'GET_CONFIG' });
  });

  ipcMain.handle('set-config', async (_, config) => {
    sendToPython({ command: 'SET_CONFIG', payload: config });
  });

  ipcMain.handle('activate-license', async (_, key) => {
    sendToPython({ command: 'ACTIVATE_LICENSE', payload: { key } });
  });
};
