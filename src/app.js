// NITO Wallet Application Entry Point 
// Main orchestrator for initialization and module coordination

import { CONFIG, VERSION, ELEMENT_IDS, UI_CONFIG } from './config.js';
import { loadExternalLibraries, areLibrariesReady } from './vendor.js';
import { eventBus, EVENTS } from './events.js';

// === LOADING MODAL SYSTEM ===
function showLoading(message) {
  try {
    let modal = document.getElementById('loadingModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'loadingModal';
      modal.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,.35);backdrop-filter:blur(4px);z-index:9999;align-items:center;justify-content:center;';
      
      const isDarkMode = document.body.getAttribute('data-theme') === 'dark';
      modal.innerHTML = `
        <div style="
          background: ${isDarkMode ? '#1a202c' : '#ffffff'};
          color: ${isDarkMode ? '#e2e8f0' : '#111111'};
          border: 1px solid ${isDarkMode ? '#4a5568' : '#e2e8f0'};
          padding: 1.5rem 2rem;
          border-radius: 16px;
          box-shadow: 0 10px 30px rgba(0,0,0,${isDarkMode ? '0.5' : '0.2'});
          text-align: center;
          min-width: 300px;
          max-width: 90vw;
          backdrop-filter: blur(10px);
        ">
          <div style="font-size:2.5rem; line-height:1; margin-bottom:1rem; animation: rotate 1.2s linear infinite;">⌛</div>
          <div class="loading-text" style="font-weight:600; font-size: 18px; margin-bottom: 0.5rem;">Actualisation du solde…</div>
          <div style="font-size: 14px; opacity: 0.7;">Scan blockchain en cours...</div>
        </div>
      `;
      document.body.appendChild(modal);
    }
    const text = modal.querySelector('.loading-text');
    if (text && message) text.textContent = message;
    modal.style.display = 'flex';
  } catch (e) {
    console.warn('Loading modal error:', e);
  }
}

function hideLoading() {
  try {
    const modal = document.getElementById('loadingModal');
    if (!modal) return;
    modal.style.display = 'none';
  } catch (e) {
    console.warn('Hide loading error:', e);
  }
}

// === BALANCE LOADING SYSTEM ===
function showBalanceLoadingSpinner(show, messageKey = 'loading.balance_refresh') {
  let modal = document.getElementById('balanceLoadingModal');
  
  if (show) {
    const t = (window.i18next && typeof window.i18next.t === 'function') 
      ? window.i18next.t 
      : (key, fallback) => fallback || key;
    
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'balanceLoadingModal';
      modal.style.cssText = `
        display: flex;
        position: fixed;
        inset: 0;
        background: rgba(0,0,0,.4);
        backdrop-filter: blur(6px);
        z-index: 10000;
        align-items: center;
        justify-content: center;
      `;
      
      document.body.appendChild(modal);
    }
    
    const isDarkMode = document.body.getAttribute('data-theme') === 'dark';
    const message = t(messageKey, 'Actualisation du solde…');
    const subtitle = t('loading.blockchain_scan', 'Scan blockchain en cours...');
    
    modal.innerHTML = `
      <div style="
        background: ${isDarkMode ? '#1a202c' : '#ffffff'};
        color: ${isDarkMode ? '#e2e8f0' : '#111111'};
        border: 1px solid ${isDarkMode ? '#4a5568' : '#e2e8f0'};
        padding: 2rem 2.5rem;
        border-radius: 20px;
        box-shadow: 0 15px 40px rgba(0,0,0,${isDarkMode ? '0.6' : '0.25'});
        text-align: center;
        min-width: 320px;
        max-width: 90vw;
        backdrop-filter: blur(15px);
        border: 2px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'};
      ">
        <div style="font-size:3rem; line-height:1; margin-bottom:1.2rem; animation: rotate 1.5s linear infinite;">⌛</div>
        <div class="loading-text" style="font-weight:700; font-size: 20px; margin-bottom: 0.8rem; color: ${isDarkMode ? '#60a5fa' : '#2563eb'};">${message}</div>
        <div style="font-size: 15px; opacity: 0.8; margin-bottom: 1rem;">${subtitle}</div>
        <div style="width: 100%; background: ${isDarkMode ? '#374151' : '#e5e7eb'}; border-radius: 10px; height: 6px; overflow: hidden;">
          <div style="width: 100%; height: 100%; background: linear-gradient(90deg, ${isDarkMode ? '#3b82f6' : '#2563eb'}, ${isDarkMode ? '#1e40af' : '#1d4ed8'}); border-radius: 10px; animation: loading-bar 2s ease-in-out infinite;"></div>
        </div>
      </div>
    `;
    
    // Ajouter l'animation CSS si elle n'existe pas
    if (!document.querySelector('#loading-bar-style')) {
      const style = document.createElement('style');
      style.id = 'loading-bar-style';
      style.textContent = `
        @keyframes loading-bar {
          0%, 100% { transform: translateX(-100%); }
          50% { transform: translateX(100%); }
        }
        @keyframes rotate {
          100% { transform: rotate(360deg); }
        }
      `;
      document.head.appendChild(style);
    }
    
    modal.style.display = 'flex';
  } else {
    if (modal) {
      modal.style.display = 'none';
    }
  }
}

// === APPLICATION STATE ===
let appInitialized = false;
let initializationPromise = null;

// === DEPENDENCY MANAGEMENT ===
class DependencyManager {
  constructor() {
    this.loadedModules = new Set();
    this.loadingPromises = new Map();
    this.moduleErrors = new Map();
  }

  async loadModule(name, loader) {
    if (this.loadedModules.has(name)) {
      return this.loadingPromises.get(name);
    }
    if (this.moduleErrors.has(name)) {
      throw this.moduleErrors.get(name);
    }
    const promise = (async () => {
      try {
        const result = await loader();
        this.loadedModules.add(name);
        return result;
      } catch (error) {
        this.moduleErrors.set(name, error);
        throw error;
      }
    })();
    this.loadingPromises.set(name, promise);
    return promise;
  }

  isLoaded(name) { return this.loadedModules.has(name); }
  getError(name) { return this.moduleErrors.get(name); }
  reset() {
    this.loadedModules.clear();
    this.loadingPromises.clear();
    this.moduleErrors.clear();
  }
}

// === MAIN APPLICATION CLASS ===
export class NITOWalletApp {
  constructor() {
    this.dependencyManager = new DependencyManager();
    this.initStartTime = Date.now();
    this.modules = new Map();
    this.eventListeners = new Map();
    this.initialized = false;
  }

  static async initialize() {
    if (initializationPromise) return initializationPromise;
    if (appInitialized) return Promise.resolve();
    const app = new NITOWalletApp();
    initializationPromise = app.start();
    return initializationPromise;
  }

  async start() {
    try {
      await this.validateEnvironment();
      await this.loadDependencies();
      await this.initializeCore();
      await this.setupUserInterface();
      await this.initializeModules();
      await this.finalizeSetup();
      this.markAsReady();
    } catch (error) {
      await this.handleInitializationError(error);
      throw error;
    }
  }

  // === ENVIRONMENT VALIDATION ===
  async validateEnvironment() {
    const requiredAPIs = [
      'crypto', 'fetch', 'localStorage', 'sessionStorage',
      'URLSearchParams', 'TextEncoder', 'TextDecoder'
    ];
    const missing = requiredAPIs.filter(api => !(api in window));
    if (missing.length > 0) throw new Error(`Missing required browser APIs: ${missing.join(', ')}`);

    try {
      localStorage.setItem('test', 'test');
      localStorage.removeItem('test');
    } catch (_) {
      console.warn('localStorage not available');
    }
  }

  // === DEPENDENCY LOADING ===
  async loadDependencies() {
    const librariesPromise = loadExternalLibraries();
    const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Libraries loading timeout')), 60000));
    await Promise.race([librariesPromise, timeoutPromise]);
    if (!areLibrariesReady()) throw new Error('Bitcoin libraries failed to initialize properly');
  }

  // === CORE INITIALIZATION ===
  async initializeCore() {
    await this.dependencyManager.loadModule('security', () => import('./security.js'));
    await this.dependencyManager.loadModule('events', () => import('./events.js'));
    await this.initializeI18n();
    this.initializeThemes();
    this.initializeErrorHandling();
  }

  // === INTERNATIONALIZATION ===
  async initializeI18n() {
    return new Promise((resolve) => {
      try {
        if (!window.i18next) { resolve(); return; }

        const savedLng = localStorage.getItem('nito_lang') || UI_CONFIG?.DEFAULT_LANGUAGE || 'fr';

        window.i18next
          .use(window.i18nextHttpBackend)
          .init({
            lng: savedLng,
            fallbackLng: UI_CONFIG?.FALLBACK_LANGUAGE || 'en',
            backend: {
              loadPath: './locales/{{lng}}.json'
            },
            interpolation: { escapeValue: false }
          }, async (err) => {
            if (err) { console.warn('i18next init error:', err); resolve(); return; }

            // Sync select initial value
            const sel = document.getElementById(ELEMENT_IDS.LANGUAGE_SELECT);
            if (sel) sel.value = window.i18next.language;

            // Apply all translations now
            this.updateTranslations();

            // React to language changes
            const changeLanguage = async (lng) => {
              await window.i18next.changeLanguage(lng);
              localStorage.setItem('nito_lang', lng);
              this.updateTranslations();
            };

            // Hook on selector
            if (sel) {
              sel.addEventListener('change', (e) => changeLanguage(e.target.value));
            }

            resolve();
          });
      } catch (error) {
        console.warn('i18next setup failed:', error);
        resolve();
      }
    });
  }

  updateTranslations() {
    if (!window.i18next) return;

    // Elements with data-i18n
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      // Support syntax: [placeholder]foo.bar
      if (key.startsWith('[')) {
        const m = key.match(/^\[(.+?)\](.+)$/);
        if (m) {
          const [, attr, realKey] = m;
          const t = window.i18next.t(realKey);
          if (t && t !== realKey) el.setAttribute(attr, t);
        }
      } else {
        const t = window.i18next.t(key);
        if (t && t !== key) el.textContent = t;
      }
    });

    // Title inside <h1> (second child node text)
    const h1 = document.querySelector('h1');
    if (h1 && h1.childNodes[1]) {
      const t = window.i18next.t('title');
      if (t && t !== 'title') h1.childNodes[1].textContent = t;
    }

    // Warning block may contain markup -> sanitize if DOMPurify is present
    const warning = document.querySelector('.warning');
    if (warning && window.DOMPurify) {
      const t = window.i18next.t('generate_section.warning');
      if (t && t !== 'generate_section.warning') {
        warning.innerHTML = window.DOMPurify.sanitize(t);
      }
    }
  }

  // === THEME SYSTEM ===
  initializeThemes() {
    const themeToggle = document.getElementById(ELEMENT_IDS.THEME_TOGGLE);
    const root = document.documentElement;
    const body = document.body;
    if (!themeToggle || !root) return;

    const getCurrentTheme = () => {
      const saved = localStorage.getItem('theme');
      if (saved === 'light' || saved === 'dark') return saved;
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    };

    const applyTheme = (theme, fromUser = false) => {
      root.setAttribute('data-theme', theme);
      body.setAttribute('data-theme', theme);
      const metaThemeColor = document.querySelector('meta[name="theme-color"]');
      if (metaThemeColor) metaThemeColor.setAttribute('content', theme === 'dark' ? '#0c0c0c' : '#ffffff');
      themeToggle.setAttribute('aria-pressed', String(theme === 'dark'));
      themeToggle.textContent = theme === 'dark' ? '☀️' : '🌙';
      if (fromUser) localStorage.setItem('theme', theme);
      eventBus.emit(EVENTS.UI_THEME_CHANGED, { theme });
    };

    applyTheme(getCurrentTheme());
    themeToggle.addEventListener('click', () => {
      const currentTheme = root.getAttribute('data-theme');
      const next = currentTheme === 'dark' ? 'light' : 'dark';
      applyTheme(next, true);
    });
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      if (!localStorage.getItem('theme')) applyTheme(e.matches ? 'dark' : 'light');
    });
  }

  // === ERROR HANDLING ===
  initializeErrorHandling() {
    window.addEventListener('error', (event) => this.handleRuntimeError(event.error));
    window.addEventListener('unhandledrejection', (event) => this.handleRuntimeError(event.reason));
  }

  // === USER INTERFACE SETUP ===
  async setupUserInterface() {
    this.setupMobileZoomControl();
    this.setupNavigationTabs();
    this.setupAuthenticationSystem();
    this.setupBalanceManagement();
    this.setupRefreshSystem();
  }

  setupMobileZoomControl() {
    const isMobile = /Mobi|Android|iPhone|iPad|iPod|Opera Mini|IEMobile|WPDesktop/.test(navigator.userAgent);
    if (!isMobile) return;

    let isZooming = false;
    document.addEventListener('touchstart', (e) => { if (e.touches.length === 2) isZooming = true; });
    document.addEventListener('touchend', () => { isZooming = false; setTimeout(() => this.resetZoom(), 300); });
    window.addEventListener('resize', () => { if (!isZooming) this.resetZoom(); });
    setInterval(() => { if (!isZooming) this.resetZoom(); }, 500);
  }

  resetZoom() {
    document.body.style.zoom = '0.8';
    const viewport = document.querySelector('meta[name="viewport"]');
    if (viewport) viewport.setAttribute('content', 'width=device-width, initial-scale=0.8, user-scalable=yes');
  }

  setupNavigationTabs() {
    const tabs = document.querySelectorAll('#mainTabs button');
    const showTab = (id) => {
      document.querySelectorAll('.tab-pane').forEach(pane => { pane.style.display = pane.id === id ? 'block' : 'none'; });
      tabs.forEach(btn => btn.classList.toggle('active', btn.dataset.tab === id));
      window.scrollTo({ top: 0, behavior: 'smooth' });
    };
    tabs.forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.dataset.tab;
        const needsImport = (target === 'tab-send' || target === 'tab-msg');
        const isImported = !!(window.isWalletReady && window.isWalletReady());
        if (needsImport && !isImported) {
          const message = window.i18next ? window.i18next.t('errors.import_first') : 'Importez d\'abord un wallet.';
          alert(message);
          showTab('tab-gen');
          return;
        }
        showTab(target);
      });
    });
    if (typeof window !== 'undefined') window.__NITOShowTab = showTab;
  }

  setupAuthenticationSystem() {
    const tabEmail = document.getElementById('tabEmail');
    const tabKey = document.getElementById('tabKey');
    const emailForm = document.getElementById('emailForm');
    const keyForm = document.getElementById('keyForm');

    if (tabEmail && tabKey && emailForm && keyForm) {
      tabEmail.addEventListener('click', () => {
        tabEmail.classList.add('active'); tabKey.classList.remove('active');
        emailForm.classList.add('active'); keyForm.classList.remove('active');
      });
      tabKey.addEventListener('click', () => {
        tabKey.classList.add('active'); tabEmail.classList.remove('active');
        keyForm.classList.add('active'); emailForm.classList.remove('active');
      });
    }
  }

  setupBalanceManagement() {
    const updateSendTabBalance = async () => {
      console.log('[REFRESH_START] updateSendTabBalance invoked');
      try {
        const selector = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE);
        const output = document.getElementById(ELEMENT_IDS.SEND_TAB_BALANCE);
        if (!selector || !output) return;

        const addressType = selector.value;
        console.log('[REFRESH_INFO] addressType:', addressType);
        let address = '';
        if (addressType === 'p2tr') {
          address = window.getTaprootAddress ? window.getTaprootAddress() : '';
        } else {
          address = window.getWalletAddress ? window.getWalletAddress() : '';
        }

        if (!address) { 
          console.warn('[REFRESH_WARN] No address for type', addressType); 
          output.textContent = '0.00000000'; 
          return; 
        }
        if (window.balance) {
          const balance = await window.balance(address);
          console.log('[REFRESH_OK] address', address, 'balance', balance);
          output.textContent = (balance || 0).toFixed(8);
        } else {
          output.textContent = '0.00000000';
        }
      } catch (error) {
        console.error('[REFRESH_ERROR] Balance update error:', error);
      }
    };

    if (typeof window !== 'undefined') window.updateSendTabBalance = updateSendTabBalance;

    document.addEventListener('change', (ev) => {
      if (ev.target && ev.target.id === ELEMENT_IDS.DEBIT_ADDRESS_TYPE) updateSendTabBalance();
    });

    const sendTabButton = document.querySelector('#mainTabs button[data-tab="tab-send"]');
    if (sendTabButton) sendTabButton.addEventListener('click', () => setTimeout(updateSendTabBalance, 100));
  }

  setupRefreshSystem() {
    // Fonction de mise à jour complète des soldes avec animation
    const refreshAllBalances = async () => {
      const t = (window.i18next && typeof window.i18next.t === 'function') 
        ? window.i18next.t 
        : (key, fallback) => fallback || key;
      
      showBalanceLoadingSpinner(true, 'loading.cache_clearing');
      
      try {
        // Clear blockchain caches if available to force a true UTXO refresh
        if (window.clearBlockchainCaches) {
          const maybePromise = window.clearBlockchainCaches();
          if (maybePromise && typeof maybePromise.then === 'function') {
            await maybePromise;
          }
          console.log('[REFRESH_INFO] Caches cleared');
        }
        
        // Attendre un peu pour que le nettoyage prenne effet
        await new Promise(r => setTimeout(r, 800));
        showBalanceLoadingSpinner(true, 'loading.utxo_scan');
        
        // Update send tab balance
        if (typeof window.updateSendTabBalance === 'function') {
          await window.updateSendTabBalance();
        }
        
        // Update total balance display
        if (window.getTotalBalance) {
          const total = await window.getTotalBalance();
          const balanceElement = document.getElementById('totalBalance');
          if (balanceElement) {
            balanceElement.textContent = total.toFixed(8) + ' NITO';
          }
        }
        
        // Success message
        showBalanceLoadingSpinner(true, 'loading.balance_updated');
        await new Promise(r => setTimeout(r, 1200));
        
      } catch (error) {
        console.error('[REFRESH_ERROR]', error);
        showBalanceLoadingSpinner(true, 'loading.update_error');
        await new Promise(r => setTimeout(r, 1500));
      } finally {
        showBalanceLoadingSpinner(false);
      }
    };

    // Export global pour les autres modules
    if (typeof window !== 'undefined') {
      window.refreshAllBalances = refreshAllBalances;
      window.showBalanceLoadingSpinner = showBalanceLoadingSpinner;
    }
  }

  // === MODULE INITIALIZATION ===
  async initializeModules() {
    await this.dependencyManager.loadModule('blockchain', () => import('./blockchain.js'));
    await this.dependencyManager.loadModule('wallet', () => import('./wallet.js'));
    await this.dependencyManager.loadModule('transactions', () => import('./transactions.js'));
    await this.dependencyManager.loadModule('messaging', () => import('./messaging.js'));
    await this.dependencyManager.loadModule('ui-handlers', () => import('./ui-handlers.js'));
    await this.waitForModulesReady();
  }

  async waitForModulesReady() {
    const maxAttempts = 30;
    for (let attempts = 0; attempts < maxAttempts; attempts++) {
      try {
        if (window.rpc) {
          const info = await window.rpc('getblockchaininfo');
          if (info) break;
        }
      } catch (_) {}
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  // === FINALIZATION ===
  async finalizeSetup() {
    await this.updateCounterDisplay();
    this.setupPeriodicTasks();
    this.registerServiceWorker();
    this.setupRefreshLabels();
    this.setupGlobalRefreshHandlers();
  }

  async updateCounterDisplay() {
    try {
      const counterElement = document.getElementById(ELEMENT_IDS.KEY_COUNTER);
      if (!counterElement) return;
      const response = await fetch(CONFIG.API.COUNTER_GET_URL);
      if (response.ok) {
        const data = await response.json();
        counterElement.textContent = data.count || 0;
      }
    } catch (_) {}
  }

  setupPeriodicTasks() {
    setInterval(() => { try { if (window.gc) window.gc(); } catch (_) {} }, CONFIG.SECURITY.CLEANUP_INTERVAL);
    setInterval(() => { if (window.clearBlockchainCaches) window.clearBlockchainCaches(); }, 600000);
  }

  registerServiceWorker() {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/sw.js').catch(() => {});
    }
  }

  setupRefreshLabels() {
    const setRefreshLabels = () => {
      try {
        const t = (window.i18next && typeof window.i18next.t === 'function')
          ? window.i18next.t('import_section.refresh_button', '🔄 Actualiser')
          : '🔄 Actualiser';
        
        // Bouton principal section import
        const mainBtn = document.getElementById('refreshBalanceButton');
        if (mainBtn) {
          mainBtn.textContent = t;
          mainBtn.style.cssText = `
            background: var(--success-gradient);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 50px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.95rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 15px rgba(79, 172, 254, 0.4);
            margin: 0.5rem;
            text-transform: none;
            letter-spacing: normal;
          `;
        }
        
        // Bouton section envoi - même style
        const sendBtn = document.getElementById(ELEMENT_IDS.REFRESH_SEND_TAB_BALANCE);
        if (sendBtn) {
          sendBtn.textContent = t;
          sendBtn.style.cssText = `
            background: var(--success-gradient);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 50px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.95rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 15px rgba(79, 172, 254, 0.4);
            margin: 0.5rem;
            text-transform: none;
            letter-spacing: normal;
          `;
        }
      } catch {}
    };

    // Application initiale
    document.addEventListener('DOMContentLoaded', setRefreshLabels);
    
    // Réappliquer lors du changement de langue
    if (window.i18next && typeof window.i18next.on === 'function') {
      window.i18next.on('languageChanged', setRefreshLabels);
    }
    
    // Export global
    if (typeof window !== 'undefined') {
      window.setRefreshLabels = setRefreshLabels;
    }

    // Appliquer immédiatement
    setTimeout(setRefreshLabels, 100);
  }

  setupGlobalRefreshHandlers() {
    // Gestionnaire unifié pour tous les boutons refresh
    document.addEventListener('click', async (ev) => {
      const btn = ev.target && ev.target.closest && ev.target.closest('button');
      if (!btn) return;
      
      const isMainRefresh = (btn.id === 'refreshBalanceButton');
      const isSendRefresh = (btn.id === ELEMENT_IDS.REFRESH_SEND_TAB_BALANCE);
      
      if (!(isMainRefresh || isSendRefresh)) return;

      ev.preventDefault();
      ev.stopPropagation();
      
      console.log('[REFRESH_CLICK]', { source: btn.id });
      
      const t = (window.i18next && typeof window.i18next.t === 'function') 
        ? window.i18next.t 
        : (key, fallback) => fallback || key;
      
      // Désactiver le bouton pendant le refresh
      const originalText = btn.textContent;
      const originalStyle = btn.style.cssText;
      
      btn.disabled = true;
      btn.textContent = t('loading.refreshing', '⌛ Actualisation...');
      btn.style.opacity = '0.7';
      btn.style.cursor = 'not-allowed';
      
      try {
        if (typeof window.refreshAllBalances === 'function') {
          await window.refreshAllBalances();
        }
        console.log('[REFRESH_DONE]', { source: btn.id });
      } catch (e) {
        console.error('[REFRESH_ERROR]', e);
      } finally {
        // Restaurer le bouton
        btn.disabled = false;
        btn.textContent = originalText;
        btn.style.cssText = originalStyle;
      }
    });

    console.log('[SETUP] Global refresh handlers initialized');
  }

  // === COMPLETION ===
  markAsReady() {
    appInitialized = true;
    const initTime = Date.now() - this.initStartTime;
    eventBus.emit(EVENTS.SYSTEM_READY, { initTime, version: VERSION.STRING, timestamp: Date.now() });
    window.dispatchEvent(new CustomEvent('nitoWalletReady', { detail: { initTime, version: VERSION.STRING } }));
    console.log(`NITO Wallet ready in ${initTime}ms - Version ${VERSION.STRING}`);
  }

  // === ERROR HANDLING ===
  async handleInitializationError(error) {
    const errorMessage = window.i18next ?
      window.i18next.t('errors.initialization_failed') :
      'Échec de l\'initialisation de l\'application. Veuillez actualiser la page.';
    try {
      const body = document.body;
      const div = document.createElement('div');
      div.style.cssText = `
        position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
        background: #ff4444; color: white; padding: 20px; border-radius: 8px;
        z-index: 10000; text-align: center; max-width: 90%;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
      `;
      div.innerHTML = `
        <h3>Erreur d'initialisation</h3>
        <p>${errorMessage}</p>
        <p style="font-size: 0.9em; opacity: 0.8; margin-top: 10px;">Erreur: ${error.message}</p>
        <button onclick="location.reload()" style="
          margin-top: 15px; padding: 10px 20px; background: white; 
          color: #ff4444; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
          Recharger la page
        </button>
      `;
      body.appendChild(div);
      setTimeout(() => { location.reload(); }, 10000);
    } catch (_) {
      alert(errorMessage + '\n\nErreur: ' + error.message);
      setTimeout(() => location.reload(), 2000);
    }
    eventBus.emit(EVENTS.SYSTEM_ERROR, { type: 'initialization_error', error: error.message, timestamp: Date.now() });
  }

  handleRuntimeError(error) {
    eventBus.emit(EVENTS.SYSTEM_ERROR, {
      type: 'runtime_error',
      error: (error && error.message) ? error.message : String(error),
      timestamp: Date.now()
    });
  }

  // === STATUS METHODS ===
  static getStatus() {
    return {
      initialized: appInitialized,
      librariesReady: areLibrariesReady(),
      version: VERSION.STRING,
      timestamp: Date.now()
    };
  }

  getModuleStatus() {
    return {
      loaded: Array.from(this.dependencyManager.loadedModules),
      errors: Object.fromEntries(this.dependencyManager.moduleErrors),
      timestamp: Date.now()
    };
  }
}

// === AUTO-INITIALIZATION ===
const initializeApp = async () => {
  try {
    await NITOWalletApp.initialize();
  } catch (error) {
    console.error('Auto-initialization failed:', error);
  }
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeApp);
} else {
  setTimeout(initializeApp, 100);
}

// === GLOBAL ACCESS ===
if (typeof window !== 'undefined') {
  window.NITOWalletApp = NITOWalletApp;
  window.initializeApp = initializeApp;
  window.showLoading = showLoading;
  window.hideLoading = hideLoading;
}

export default NITOWalletApp;

console.log('NITO Wallet App module loaded');