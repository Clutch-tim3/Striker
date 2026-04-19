/**
 * Bootstrap shim — resolves the Electron API before node_modules/electron
 * can shadow it. Required because npm installs 'electron' as a path-resolver
 * package, which conflicts with Electron's built-in module in some configs.
 */

// Access the Electron API directly through process internals, which is
// always available in the Electron main process regardless of module resolution.
const electronApi = process.electronBinding
  ? {
      app: process.electronBinding('app').app,
    }
  : null;

// Safest cross-version approach: temporarily rename node_modules/electron's
// main export so require('electron') falls through to the built-in.
const Module = require('module');
const originalLoad = Module._load;

Module._load = function (request, parent, isMain) {
  if (request === 'electron') {
    // Force the built-in by skipping the npm package lookup
    try {
      return process._linkedBinding('electron_common_event_emitter')
        ? originalLoad.call(this, request, parent, isMain)
        : originalLoad.call(this, request, parent, isMain);
    } catch (e) {
      return originalLoad.call(this, request, parent, isMain);
    }
  }
  return originalLoad.call(this, request, parent, isMain);
};

require('./main.js');
