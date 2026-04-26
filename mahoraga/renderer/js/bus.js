'use strict';

/**
 * bus.js — single event bus for all Python IPC events.
 * Call Bus.init() once in DOMContentLoaded.
 * Subscribe with Bus.on(eventType, callback).
 * All pages use this instead of calling window.mahoraga.onEvent directly.
 */
const Bus = (function () {
  const _subs = {};

  function on(type, cb) {
    (_subs[type] = _subs[type] || []).push(cb);
  }

  function off(type, cb) {
    if (_subs[type]) _subs[type] = _subs[type].filter(x => x !== cb);
  }

  function _dispatch(type, data) {
    (_subs[type] || []).forEach(cb => {
      try { cb(data); } catch (e) { console.error('[Bus]', type, e); }
    });
    (_subs['*'] || []).forEach(cb => {
      try { cb(type, data); } catch (e) {}
    });
  }

  function init() {
    if (!window.mahoraga) return;
    window.mahoraga.onEvent(event => _dispatch(event.type, event.data));
  }

  return { on, off, init };
})();

window.Bus = Bus;
