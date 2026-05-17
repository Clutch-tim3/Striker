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
  console.log('DEBUG: starting Python backend');
  const pythonPath = getPythonPath();
  const projectRoot = path.join(__dirname, '..');

  pythonProcess = app.isPackaged
    ? spawn(pythonPath)
    : spawn('python3', [pythonPath], {
        cwd: projectRoot,
        env: { ...process.env, PYTHONPATH: projectRoot },
      });

  let _pythonBuffer = '';
  pythonProcess.stdout.on('data', (data) => {
    const text = data.toString();
    console.log('DEBUG Python stdout raw:', text);
    _pythonBuffer += text;
    const lines = _pythonBuffer.split('\n');
    _pythonBuffer = lines.pop(); // keep incomplete trailing piece for next chunk
    lines.forEach(line => {
      if (!line.trim()) return;
      console.log('DEBUG Python stdout line:', line);
      try {
        const msg = JSON.parse(line);
        console.log('DEBUG Python parsed message:', msg);
        handlePythonMessage(msg);
      } catch (err) {
        console.error('DEBUG Python parse failed:', err, 'line:', line);
      }
    });
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error('[Python]', data.toString());
  });

  pythonProcess.on('error', (err) => {
    console.error('DEBUG pythonProcess error:', err);
  });

  pythonProcess.on('exit', (code) => {
    console.log('[Python] exited with code', code);
    if (code !== 0) setTimeout(startPythonBackend, 2000);
  });
}

function handlePythonMessage(msg) {
  console.log('DEBUG: handlePythonMessage:', msg);
  if (msg.type === 'ARCHIVE_STATS') {
    console.log('DEBUG: Received ARCHIVE_STATS from Python:', msg.data);
  }
  if (!mainWindow) return;
  mainWindow.webContents.send('python-event', msg);
}

function sendToPython(msg) {
  console.log('DEBUG: sendToPython called with:', msg);
  if (!pythonProcess) {
    console.log('DEBUG: no pythonProcess');
    return;
  }
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
      nodeIntegration: true,
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
  console.log('DEBUG main ipc handle:', msg);
  sendToPython(msg);
  return { ok: true };
});

require('./ipc-handlers')(ipcMain, sendToPython);

