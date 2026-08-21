/**
 * FIBEMATE Tauri Bridge v3.0
 * Polyfills window.electronAPI using Tauri v2 native APIs.
 * Load BEFORE main-v3.js — existing frontend code uses window.electronAPI.*
 */
(async function initTauriBridge() {
  'use strict';

  const isTauri = !!(window.__TAURI__ || window.__TAURI_INTERNALS__);

  if (!isTauri) {
    console.warn('[TauriBridge] Not running in Tauri. Using stub APIs.');
    window.electronAPI = createStubAPI();
    return;
  }

  try {
    const { getCurrentWindow } = window.__TAURI__.window;
    const { invoke } = window.__TAURI__.core;
    const { listen } = window.__TAURI__.event;

    const appWindow = getCurrentWindow();

    // ================================================
    // Electron API — compatible surface
    // ================================================
    window.electronAPI = {
      platform: await invoke('get_platform'),

      // Flat aliases for legacy code compatibility
      getWSUrl: () => invoke('get_ws_url'),
      getVersion: () => invoke('get_version'),
      getPlatform: () => invoke('get_platform'),
      getUserDataPath: () => invoke('get_user_data_path'),

      // --- Window control ---
      window: {
        minimize: () => appWindow.minimize(),
        maximize: () => appWindow.toggleMaximize(),
        close: () => appWindow.close(),
        isMaximized: () => appWindow.isMaximized(),
        onMaximizeChange: (callback) => {
          let wasMaximized = false;
          appWindow.onResized(async () => {
            const isMax = await appWindow.isMaximized();
            if (isMax !== wasMaximized) {
              wasMaximized = isMax;
              callback(isMax);
            }
          });
        }
      },

      // --- File dialogs ---
      file: {
        async openFile(options = {}) {
          try {
            const { open } = await import('@tauri-apps/plugin-dialog');
            const selected = await open({
              multiple: false,
              filters: mapFilters(options.filters)
            });
            const paths = selected ? [selected] : [];
            if (paths.length) {
              const { readFile } = await import('@tauri-apps/plugin-fs');
              return { canceled: false, filePaths: paths, fileContents: [await readFile(paths[0])] };
            }
            return { canceled: true, filePaths: [], fileContents: [] };
          } catch (e) {
            console.error('[Bridge] openFile:', e);
            return { canceled: true, filePaths: [], fileContents: [] };
          }
        },

        async openFiles(options = {}) {
          try {
            const { open } = await import('@tauri-apps/plugin-dialog');
            const selected = await open({
              multiple: true,
              filters: mapFilters(options.filters)
            });
            const paths = selected || [];
            if (paths.length) {
              const { readFile } = await import('@tauri-apps/plugin-fs');
              const contents = [];
              for (const p of paths) contents.push(await readFile(p));
              return { canceled: false, filePaths: paths, fileContents: contents };
            }
            return { canceled: true, filePaths: [], fileContents: [] };
          } catch (e) {
            console.error('[Bridge] openFiles:', e);
            return { canceled: true, filePaths: [], fileContents: [] };
          }
        },

        async saveFile(defaultName = 'file', options = {}) {
          try {
            const { save } = await import('@tauri-apps/plugin-dialog');
            const filePath = await save({
              defaultPath: defaultName,
              filters: mapFilters(options.filters)
            });
            return { canceled: !filePath, filePath: filePath || null };
          } catch (e) {
            console.error('[Bridge] saveFile:', e);
            return { canceled: true, filePath: null };
          }
        },

        async read(filePath) {
          const { readFile } = await import('@tauri-apps/plugin-fs');
          return readFile(filePath);
        },

        async write(filePath, data) {
          const { writeFile } = await import('@tauri-apps/plugin-fs');
          const contents = typeof data === 'string'
            ? new TextEncoder().encode(data)
            : new Uint8Array(data);
          await writeFile(filePath, contents);
          return true;
        }
      },

      // --- Notifications ---
      notification: {
        async show(title, body) {
          try {
            const { sendNotification, isPermissionGranted, requestPermission }
              = await import('@tauri-apps/plugin-notification');
            if (!(await isPermissionGranted())) await requestPermission();
            sendNotification({ title: title || 'FIBEMATE', body: body || '' });
          } catch (e) {
            console.warn('[Bridge] notification:', e);
          }
        }
      },

      // --- App info ---
      app: {
        getVersion: () => invoke('get_version'),
        getPlatform: () => invoke('get_platform'),
        getLocale: () => invoke('get_locale'),
        getWSUrl: () => invoke('get_ws_url'),
        getUserDataPath: () => invoke('get_user_data_path')
      },

      // --- Clipboard ---
      clipboard: {
        readText: async () => {
          try {
            const { readText } = await import('@tauri-apps/plugin-clipboard-manager');
            return await readText();
          } catch { return ''; }
        },
        writeText: async (text) => {
          try {
            const { writeText } = await import('@tauri-apps/plugin-clipboard-manager');
            await writeText(text);
          } catch {}
        }
      },

      // --- Events ---
      on: (channel, callback) => {
        if (!window.__fibemate_unlisteners) window.__fibemate_unlisteners = new Map();
        listen(channel, (event) => callback(event.payload)).then(unlisten => {
          window.__fibemate_unlisteners.set(channel, unlisten);
        });
      },
      off: (channel) => {
        const ul = window.__fibemate_unlisteners?.get(channel);
        if (ul) { ul(); window.__fibemate_unlisteners.delete(channel); }
      },
      once: (channel, callback) => {
        listen(channel, (event) => { callback(event.payload); }).then(unlisten => {
          setTimeout(() => unlisten(), 10);
        });
      }
    };

    console.log('[TauriBridge] Ready. Platform:', window.electronAPI.platform);

  } catch (e) {
    console.error('[TauriBridge] Init failed, falling back to stub:', e);
    window.electronAPI = createStubAPI();
  }
})();

// --- Helpers ---
function mapFilters(filters) {
  if (!Array.isArray(filters) || !filters.length) return undefined;
  return filters.map(f => ({
    name: f.name,
    extensions: f.extensions || ['*']
  }));
}

function createStubAPI() {
  return {
    platform: 'browser',
    // Flat aliases for legacy code
    getWSUrl: async () => 'ws://localhost:3001/ws',
    getVersion: async () => '3.0.0-dev',
    getPlatform: async () => 'browser',
    getUserDataPath: async () => '',
    window: { minimize() {}, maximize() {}, close() {}, isMaximized: async () => false, onMaximizeChange() {} },
    file: {
      openFile: async () => ({ canceled: true, filePaths: [] }),
      openFiles: async () => ({ canceled: true, filePaths: [] }),
      saveFile: async () => ({ canceled: true, filePath: null }),
      read: async () => { throw new Error('Not in Tauri'); },
      write: async () => { throw new Error('Not in Tauri'); }
    },
    notification: {
      show(title, body) {
        if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
          new Notification(title, { body });
        }
      }
    },
    app: {
      getVersion: async () => '3.0.0-dev',
      getPlatform: async () => 'browser',
      getLocale: async () => 'en-US',
      getWSUrl: async () => 'ws://localhost:3001/ws',
      getUserDataPath: async () => ''
    },
    clipboard: {
      readText: async () => { try { return await navigator.clipboard.readText(); } catch { return ''; } },
      writeText: async (t) => { try { await navigator.clipboard.writeText(t); } catch {} }
    },
    on() {}, off() {}, once() {}
  };
}