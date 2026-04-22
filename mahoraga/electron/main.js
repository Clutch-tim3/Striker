const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let pythonProcess;

function getPythonPath() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, 'python', 'mahoraga');
  }
  return path.join(__dirname, '..', 'python', 'main.py');
}

function startPythonBackend() {
  const pythonPath = getPythonPath();
  const projectRoot = path.join(__dirname, '..');

  pythonProcess = app.isPackaged
    ? spawn(pythonPath)
    : spawn('python3', [pythonPath], {
        cwd: projectRoot,
        env: { ...process.env, PYTHONPATH: projectRoot },
      });

  pythonProcess.stdout.on('data', (data) => {
    const lines = data.toString().split('\n').filter(Boolean);
    lines.forEach(line => {
      try {
        const msg = JSON.parse(line);
        handlePythonMessage(msg);
      } catch {}
    });
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error('[Python]', data.toString());
  });

  pythonProcess.on('exit', (code) => {
    console.log('[Python] exited with code', code);
    if (code !== 0) setTimeout(startPythonBackend, 2000);
  });
}

function handlePythonMessage(msg) {
  if (!mainWindow) return;
  mainWindow.webContents.send('python-event', msg);
}

function sendToPython(msg) {
  if (!pythonProcess) return;
  pythonProcess.stdin.write(JSON.stringify(msg) + '\n');
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 640,
    backgroundColor: '#07070A',
    titleBarStyle: 'hiddenInset',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(() => {
  startPythonBackend();
  createWindow();
  if (app.isPackaged) {
    const { autoUpdater } = require('electron-updater');
    autoUpdater.on('update-available', () => {
      dialog.showMessageBox({
        type: 'info',
        title: 'Update available',
        message: 'A new version of Mahoraga is available. It will download in the background.',
        buttons: ['OK'],
      });
    });
    autoUpdater.on('update-downloaded', () => {
      dialog.showMessageBox({
        type: 'info',
        title: 'Update ready',
        message: 'Mahoraga has been updated. Restart to apply.',
        buttons: ['Restart now', 'Later'],
      }).then(({ response }) => {
        if (response === 0) autoUpdater.quitAndInstall();
      });
    });
    autoUpdater.checkForUpdatesAndNotify();
  }
});

app.on('window-all-closed', () => {
  if (pythonProcess) pythonProcess.kill();
  if (process.platform !== 'darwin') app.quit();
});

ipcMain.handle('send-to-python', async (event, msg) => {
  sendToPython(msg);
  return { ok: true };
});

require('./ipc-handlers')(ipcMain, sendToPython);
