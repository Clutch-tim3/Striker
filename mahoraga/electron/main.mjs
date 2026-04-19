import electronMain from 'electron/main';
const { app, BrowserWindow, ipcMain } = electronMain;
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

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
    backgroundColor: '#F9F8F7',
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
});

app.on('window-all-closed', () => {
  if (pythonProcess) pythonProcess.kill();
  if (process.platform !== 'darwin') app.quit();
});

ipcMain.handle('send-to-python', async (event, msg) => {
  sendToPython(msg);
  return { ok: true };
});

const registerHandlers = require('./ipc-handlers.js');
registerHandlers(ipcMain, sendToPython);
