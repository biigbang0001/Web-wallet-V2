import { VERSION, CONFIG, ELEMENT_IDS, UI_CONFIG, OPERATION_STATE, FEATURE_FLAGS, getTranslation } from './config.js';
import { loadExternalLibraries, areLibrariesReady } from './vendor.js';
import { eventBus, EVENTS } from './events.js';
import { showLoading, hideLoading, showBalanceLoadingSpinner } from './ui-popups.js';

// === APPLICATION STATE MANAGEMENT ===
class AppState {
  constructor() {
    this.state = {
      walletReady: false,
      walletType: null,
      addresses: {},
      balance: 0,
      pendingTransactions: new Set(),
      activeOperations: new Set(),
      initialized: false,
      theme: 'light',
      language: 'en'
    };
    this.listeners = new Map();
  }

  set(key, value) {
    const oldValue = this.state[key];
    this.state[key] = value;
    this.notify(key, value, oldValue);
  }

  get(key) {
    return this.state[key];
  }

  subscribe(key, callback) {
    if (!this.listeners.has(key)) {
      this.listeners.set(key, new Set());
    }
    this.listeners.get(key).add(callback);
    return () => this.listeners.get(key).delete(callback);
  }

  notify(key, newValue, oldValue) {
    const callbacks = this.listeners.get(key);
    if (callbacks) {
      callbacks.forEach(cb => {
        try {
          cb(newValue, oldValue);
        } catch (error) {
          console.error('[STATE] Listener error:', error);
        }
      });
    }
  }

  reset() {
    Object.keys(this.state).forEach(key => {
      if (key !== 'theme' && key !== 'language') {
        this.set(key, null);
      }
    });
    this.state.activeOperations.clear();
    this.state.pendingTransactions.clear();
  }
}

const appState = new AppState();

// === OPERATION STATE MANAGEMENT ===
export function startOperation(operationType) {
  appState.state.activeOperations.add(operationType);
  appState.notify('activeOperations', appState.state.activeOperations);
}

export function endOperation(operationType) {
  appState.state.activeOperations.delete(operationType);
  appState.notify('activeOperations', appState.state.activeOperations);
}

export function isOperationActive(operationType = null) {
  if (operationType) {
    return appState.state.activeOperations.has(operationType);
  }
  return appState.state.activeOperations.size > 0;
}

// === AUTO RELOAD ON KEY CLEAR ===
function setupAutoReloadOnKeyClear() {
  if (!FEATURE_FLAGS.AUTO_RELOAD_ON_KEY_CLEAR) return;
  
  let clearDetected = false;
  let clearTimer = null;
  
  const handleKeyClear = () => {
    if (clearDetected) return;
    clearDetected = true;
    
    if (clearTimer) clearTimeout(clearTimer);
    
    if (isOperationActive()) {
      clearTimer = setTimeout(() => {
        if (!isOperationActive()) {
          executeAutoReload();
        } else {
          handleKeyClear();
        }
      }, 5000);
      return;
    }
    
    executeAutoReload();
  };
  
  const executeAutoReload = () => {
    const isDarkMode = appState.get('theme') === 'dark';
    const overlay = document.createElement('div');
    overlay.style.cssText = `
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.8);
      z-index: 99999;
      display: flex;
      align-items: center;
      justify-content: center;
      backdrop-filter: blur(10px);
    `;
    
    const sessionExpiredText = getTranslation('security.session_expired_title', 'Session expired');
    const reloadingText = getTranslation('security.auto_reload_message', 'Auto-reloading...');
    
    overlay.innerHTML = `
      <div style="
        background: ${isDarkMode ? '#1a202c' : '#ffffff'};
        color: ${isDarkMode ? '#e2e8f0' : '#111111'};
        padding: 2rem;
        border-radius: 16px;
        text-align: center;
        box-shadow: 0 20px 50px rgba(0,0,0,0.5);
      ">
        <div style="font-size: 3rem; margin-bottom: 1rem;">🔄</div>
        <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem;">${sessionExpiredText}</div>
        <div style="opacity: 0.8;">${reloadingText}</div>
      </div>
    `;
    
    document.body.appendChild(overlay);
    
    setTimeout(() => {
      window.location.reload();
    }, 2000);
  };
  
  const unsubscribe1 = eventBus.on(EVENTS.KEYS_CLEARED, handleKeyClear);
  const unsubscribe2 = eventBus.on(EVENTS.SESSION_EXPIRED, handleKeyClear);
  
  return () => {
    if (clearTimer) clearTimeout(clearTimer);
    unsubscribe1();
    unsubscribe2();
  };
}

// === MAIN APPLICATION CLASS ===
export class NITOWalletApp {
  constructor() {
    this.dependencyManager = new DependencyManager();
    this.initStartTime = Date.now();
    this.modules = new Map();
    this.eventListeners = new Map();
    this.initialized = false;
    this.translationRetryCount = 0;
    this.timers = [];
    this.cleanupFunctions = [];
  }

  static async initialize() {
    if (initializationPromise) return initializationPromise;
    if (appInitialized) return Promise.resolve();
    const app = new NITOWalletApp();
    initializationPromise = app.start();
    return initializationPromise;
  }

  async start() {
    const loadingOverlay = document.getElementById('initialLoadingOverlay');
    if (loadingOverlay) loadingOverlay.style.display = 'flex';
    
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
    if (missing.length > 0) {
      const errorMsg = getTranslation('errors.missing_apis', 'Missing required browser APIs: {{apis}}', { apis: missing.join(', ') });
      throw new Error(errorMsg);
    }

    try {
      localStorage.setItem('test', 'test');
      localStorage.removeItem('test');
    } catch (_) {}
  }

  // === DEPENDENCY LOADING ===
  async loadDependencies() {
    const librariesPromise = loadExternalLibraries();
    const timeoutPromise = new Promise((_, reject) => setTimeout(() => {
      const errorMsg = getTranslation('errors.libraries_timeout', 'Libraries loading timeout');
      reject(new Error(errorMsg));
    }, 60000));
    
    await Promise.race([librariesPromise, timeoutPromise]);
    
    if (!areLibrariesReady()) {
      const errorMsg = getTranslation('errors.libraries_failed', 'Bitcoin libraries failed to initialize properly');
      throw new Error(errorMsg);
    }
  }

  // === CORE INITIALIZATION ===
  async initializeCore() {
    await this.dependencyManager.loadModule('security', () => import('./security.js'));
    
    const { initializeSecurity } = await import('./security.js');
    window.keyManager = await initializeSecurity();
    
    if (!window.keyManager) {
      throw new Error('Failed to initialize KeyManager');
    }
    
    await this.dependencyManager.loadModule('events', () => import('./events.js'));
    await this.initializeI18n();
    this.initializeThemes();
    this.initializeErrorHandling();
    
    const cleanupAutoReload = setupAutoReloadOnKeyClear();
    this.cleanupFunctions.push(cleanupAutoReload);
  }

  // === I18N INITIALIZATION ===
  async initializeI18n() {
    return new Promise((resolve) => {
      try {
        if (!window.i18next || !window.i18nextHttpBackend) { 
          resolve(); 
          return; 
        }

        const validLanguages = ['fr', 'en', 'de', 'es', 'nl', 'ru', 'zh'];
        const savedLng = localStorage.getItem('nito_lang');
        let targetLng = 'en';

        if (savedLng && validLanguages.includes(savedLng)) {
          targetLng = savedLng;
        } else if (savedLng && !validLanguages.includes(savedLng)) {
          localStorage.removeItem('nito_lang');
        }
        
        appState.set('language', targetLng);
        console.log(`[i18n] Initializing with language: ${targetLng}`);

        window.i18next
          .use(window.i18nextHttpBackend)
          .init({
            lng: targetLng,
            fallbackLng: 'en',
            backend: {
              loadPath: './locales/{{lng}}.json'
            },
            interpolation: { escapeValue: false },
            debug: false,
            load: 'languageOnly',
            preload: [targetLng],
            initImmediate: false
          }, async (err) => {
            if (err) { 
              console.warn('[i18n] Init error:', err);
              if (targetLng !== 'en') {
                await this.retryI18nWithFallback();
              }
              resolve(); 
              return; 
            }

            console.log(`[i18n] Successfully initialized with: ${targetLng}`);
            await this.applyTranslationsWithRetry();

            const changeLanguage = async (lng) => {
              try {
                if (!validLanguages.includes(lng)) {
                  console.warn(`[i18n] Invalid language: ${lng}`);
                  return;
                }
                console.log(`[i18n] Changing language to: ${lng}`);
                localStorage.setItem('nito_lang', lng);
                appState.set('language', lng);
                await window.i18next.changeLanguage(lng);
                await this.applyTranslationsWithRetry();
                
                const selector = document.getElementById(ELEMENT_IDS.LANGUAGE_SELECT);
                if (selector && selector.value !== lng) {
                  selector.value = lng;
                  console.log(`[i18n] Selector synchronized to: ${lng}`);
                }
              } catch (error) {
                console.warn('[i18n] Language change failed:', error);
              }
            };

            this.setupLanguageSelector(changeLanguage, targetLng, validLanguages);
            resolve();
          });
      } catch (error) {
        console.error('[i18n] Critical error:', error);
        resolve();
      }
    });
  }

  setupLanguageSelector(changeLanguage, initialLang, validLanguages) {
    const selector = document.getElementById(ELEMENT_IDS.LANGUAGE_SELECT);
    if (!selector) {
      console.warn('[i18n] Language selector not found');
      return;
    }

    selector.value = initialLang;
    
    const newSelector = selector.cloneNode(true);
    selector.parentNode.replaceChild(newSelector, selector);
    
    newSelector.value = initialLang;
    
    newSelector.addEventListener('change', (e) => {
      const selectedLang = e.target.value;
      if (validLanguages.includes(selectedLang) && selectedLang !== window.i18next.language) {
        changeLanguage(selectedLang);
      }
    });

    setTimeout(() => {
      const currentLang = window.i18next.language || initialLang;
      if (newSelector.value !== currentLang) {
        newSelector.value = currentLang;
      }
    }, 500);
  }

  async retryI18nWithFallback() {
    try {
      await window.i18next.changeLanguage('en');
      localStorage.setItem('nito_lang', 'en');
      appState.set('language', 'en');
    } catch (error) {}
  }

  async applyTranslationsWithRetry() {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await this.updateTranslations();
        return;
      } catch (error) {
        if (attempt < 2) {
          await new Promise(r => setTimeout(r, 1000));
        }
      }
    }
  }

  async updateTranslations() {
    if (!window.i18next) return;

    console.log(`[i18n] Applying translations, attempt ${this.translationRetryCount + 1}`);

    await new Promise(resolve => {
      if (document.readyState === 'complete') {
        resolve();
      } else {
        window.addEventListener('load', resolve, { once: true });
      }
    });

    const currentLang = window.i18next.language;
    console.log(`[i18n] Updating translations for language: ${currentLang}`);
    
    let updatedCount = 0;

    document.querySelectorAll('[data-i18n]').forEach(el => {
      try {
        const key = el.getAttribute('data-i18n');
        if (key.startsWith('[')) {
          const m = key.match(/^\[(.+?)\](.+)$/);
          if (m) {
            const [, attr, realKey] = m;
            const t = window.i18next.t(realKey);
            if (t && t !== realKey) {
              el.setAttribute(attr, t);
              updatedCount++;
            }
          }
        } else {
          const t = window.i18next.t(key);
          if (t && t !== key) {
            el.textContent = t;
            updatedCount++;
          }
        }
      } catch (error) {
        console.warn('[i18n] Element update error:', error);
      }
    });

    const h1 = document.querySelector('h1');
    if (h1 && h1.childNodes[1]) {
      const t = window.i18next.t('title');
      if (t && t !== 'title') {
        h1.childNodes[1].textContent = t;
        updatedCount++;
      }
    }

    const warning = document.querySelector('.warning');
    if (warning && window.DOMPurify) {
      const timerElement = document.getElementById('inactivityTimer');
      const currentTimerText = timerElement ? timerElement.textContent : '[10:00]';
      
      const t = window.i18next.t('generate_section.warning');
      if (t && t !== 'generate_section.warning') {
        const translatedWithTimer = `<span id="inactivityTimer">${currentTimerText}</span> ${t}`;
        warning.innerHTML = window.DOMPurify.sanitize(translatedWithTimer);
        updatedCount++;
      }
    }
    
    const selector = document.getElementById(ELEMENT_IDS.LANGUAGE_SELECT);
    if (selector && window.i18next) {
      const currentLang = window.i18next.language;
      if (selector.value !== currentLang) {
        selector.value = currentLang;
        console.log(`[i18n] Selector synchronized to: ${currentLang}`);
      }
    }

    console.log(`[i18n] Updated ${updatedCount} elements with translations`);
  }

  // === THEME INITIALIZATION ===
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
      appState.set('theme', theme);
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
    this.setupAddressTypeChangeListener();
  }

  setupMobileZoomControl() {
    const isMobile = /Mobi|Android|iPhone|iPad|iPod|Opera Mini|IEMobile|WPDesktop/.test(navigator.userAgent);
    if (!isMobile) return;

    let isZooming = false;
    document.addEventListener('touchstart', (e) => { if (e.touches.length === 2) isZooming = true; });
    document.addEventListener('touchend', () => { isZooming = false; setTimeout(() => this.resetZoom(), 300); });
    window.addEventListener('resize', () => { if (!isZooming) this.resetZoom(); });
    
    const zoomTimer = setInterval(() => { if (!isZooming) this.resetZoom(); }, 500);
    this.timers.push(zoomTimer);
  }

  resetZoom() {
    document.body.style.zoom = '0.8';
    const viewport = document.querySelector('meta[name="viewport"]');
    if (viewport) viewport.setAttribute('content', 'width=device-width, initial-scale=0.8, user-scalable=yes');
  }

  setupNavigationTabs() {
    const tabs = document.querySelectorAll('#mainTabs button');
    const showTab = (id) => {
      if (window.keyManager && typeof window.keyManager.updateAccess === 'function') {
        window.keyManager.updateAccess();
      }
      
      document.querySelectorAll('.tab-pane').forEach(pane => { 
        pane.style.display = pane.id === id ? 'block' : 'none'; 
      });
      tabs.forEach(btn => btn.classList.toggle('active', btn.dataset.tab === id));
      window.scrollTo({ top: 0, behavior: 'smooth' });
    };
    tabs.forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.dataset.tab;
        const needsImport = (target === 'tab-send' || target === 'tab-msg');
        
        const isImported = !!(window.bech32Address || window.taprootAddress);
        
        if (needsImport && !isImported) {
          const message = getTranslation('errors.import_first', 'Import a wallet first.');
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
        emailForm.style.display = 'block';
        keyForm.style.display = 'none';
        
        tabKey.style.display = 'block';
        tabEmail.style.display = 'block';
      });
      tabKey.addEventListener('click', () => {
        tabKey.classList.add('active'); tabEmail.classList.remove('active');
        keyForm.classList.add('active'); emailForm.classList.remove('active');
        keyForm.style.display = 'block';
        emailForm.style.display = 'none';
        
        tabEmail.style.display = 'block';
        tabKey.style.display = 'block';
      });
    }
  }

  setupBalanceManagement() {
    const updateSendTabBalance = async () => {
      if (isOperationActive('balance-refresh')) {
        return;
      }
      
      startOperation('balance-refresh');
      
      try {
        const selector = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE);
        const output = document.getElementById(ELEMENT_IDS.SEND_TAB_BALANCE);
        if (!selector || !output) return;

        const addressType = selector.value;
        let address = '';
        if (addressType === 'p2tr') {
          address = window.getTaprootAddress ? window.getTaprootAddress() : '';
        } else {
          address = window.getWalletAddress ? window.getWalletAddress() : '';
        }

        if (!address) { 
          output.textContent = '0.00000000'; 
          return; 
        }
        
        if (window.balance) {
          const isHD = window.importType === 'hd';
          const hdWallet = isHD && window.hdManager ? window.hdManager.hdWallet : null;
          const balance = await window.balance(address, isHD, hdWallet);
          output.textContent = (balance || 0).toFixed(8);
          appState.set('balance', balance || 0);
        } else {
          output.textContent = '0.00000000';
        }
      } catch (error) {
        console.error('[BALANCE] Update error:', error);
      } finally {
        endOperation('balance-refresh');
      }
    };

    if (typeof window !== 'undefined') window.updateSendTabBalance = updateSendTabBalance;

    const sendTabButton = document.querySelector('#mainTabs button[data-tab="tab-send"]');
    if (sendTabButton) sendTabButton.addEventListener('click', () => setTimeout(updateSendTabBalance, 100));
  }

  setupRefreshSystem() {
    document.addEventListener('click', async (ev) => {
      const btn = ev.target && ev.target.closest && ev.target.closest('button');
      if (!btn) return;
      
      const isMainRefresh = (btn.id === 'refreshBalanceButton');
      const isSendRefresh = (btn.id === ELEMENT_IDS.REFRESH_SEND_TAB_BALANCE);
      
      if (!(isMainRefresh || isSendRefresh)) return;

      ev.preventDefault();
      ev.stopPropagation();
      
      const originalText = btn.textContent;
      const originalDisabled = btn.disabled;
      
      btn.disabled = true;
      btn.textContent = getTranslation('loading.refreshing', 'Refreshing...');
      btn.style.opacity = '0.7';
      btn.style.cursor = 'not-allowed';
      
      try {
        if (window.refreshAllBalances) {
          await window.refreshAllBalances();
        }
      } catch (e) {
        console.error('[REFRESH] Error:', e);
      } finally {
        btn.disabled = originalDisabled;
        btn.textContent = originalText;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
      }
    });
  }

  setupAddressTypeChangeListener() {
    document.addEventListener('change', (ev) => {
      if (ev.target && ev.target.id === ELEMENT_IDS.DEBIT_ADDRESS_TYPE) {
        setTimeout(() => {
          if (window.refreshAllBalances) {
            window.refreshAllBalances();
          }
        }, 200);
      }
    });
  }

  // === MODULE INITIALIZATION ===
  async initializeModules() {
    await this.dependencyManager.loadModule('blockchain', () => import('./blockchain.js'));
    await this.dependencyManager.loadModule('wallet', () => import('./wallet.js'));
    await this.dependencyManager.loadModule('transactions', () => import('./transactions.js'));
    await this.dependencyManager.loadModule('messaging', () => import('./messaging.js'));
    await this.dependencyManager.loadModule('ui-handlers', () => import('./ui-handlers.js'));
    await this.waitForModulesReady();
    this.setupTransactionWrapper();
  }

  setupTransactionWrapper() {
    if (window.TransactionBuilder && window.filterUtxosByContext && !window.signTxWithPSBT) {
      window.signTxWithPSBT = async (destinationAddress, amountNito, isConsolidation = false, options = {}) => {
        try {
          const isHD = window.importType === 'hd';
          const hdWallet = isHD && window.hdManager ? await window.hdManager.getHDWallet() : null;

          const selectedType = document.getElementById('debitAddressType')?.value || 'bech32';
          const sourceType = selectedType === 'p2tr' ? 'p2tr' : 'bech32';

          let sourceAddress = '';
          if (sourceType === 'p2tr') {
            sourceAddress = window.taprootAddress || '';
          } else {
            sourceAddress = window.bech32Address || '';
          }

          if (!sourceAddress) {
            throw new Error('Source address not found');
          }

          let amountSats = Math.round(amountNito * 1e8);

          const allUtxos = await window.utxos(sourceAddress, isHD, hdWallet);
          
          if (!allUtxos || allUtxos.length === 0) {
            throw new Error('No UTXOs available');
          }

          const { usableUtxos } = window.filterUtxosByContext(allUtxos, 'normal');

          if (!usableUtxos.length) {
            throw new Error('No suitable UTXOs available');
          }

          const sortedUtxos = usableUtxos.sort((a, b) => b.amount - a.amount);

          const transactionBuilder = new window.TransactionBuilder();
          const feeRate = await transactionBuilder.feeManager.getRealFeeRate();

          let selectedUtxos = [];
          let totalInput = 0;
          const inputType = sourceType === 'p2tr' ? 'p2tr' : 'p2wpkh';

          if (options.isMaxSend === true) {
            selectedUtxos = [...sortedUtxos];
            totalInput = selectedUtxos.reduce((sum, utxo) => sum + Math.round(utxo.amount * 1e8), 0);
            
            const vbytes = transactionBuilder.feeManager.estimateVBytes(inputType, selectedUtxos.length, 1);
            const estimatedFee = transactionBuilder.feeManager.calculateFeeForVsize(vbytes, feeRate);
            amountSats = totalInput - estimatedFee;
            
          } else {
            for (const utxo of sortedUtxos) {
              selectedUtxos.push(utxo);
              totalInput += Math.round(utxo.amount * 1e8);

              const vbytes = transactionBuilder.feeManager.estimateVBytes(inputType, selectedUtxos.length, 2);
              const estimatedFee = transactionBuilder.feeManager.calculateFeeForVsize(vbytes, feeRate);

              if (totalInput >= amountSats + estimatedFee + 546) {
                break;
              }
            }

            const vbytes = transactionBuilder.feeManager.estimateVBytes(inputType, selectedUtxos.length, 2);
            const estimatedFee = transactionBuilder.feeManager.calculateFeeForVsize(vbytes, feeRate);

            if (totalInput < amountSats + estimatedFee) {
              throw new Error('Insufficient funds');
            }
          }

          const result = await transactionBuilder.buildAndSignTransaction(
            destinationAddress,
            amountSats,
            selectedUtxos,
            isConsolidation,
            sourceType,
            options.isMaxSend === true
          );

          return result;

        } catch (error) {
          console.error('[SIGN-TX] Error:', error);
          throw error;
        }
      };
      
    }
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
    this.setupRefreshLabels();
    
    const walletUnsubscribe = appState.subscribe('walletReady', (isReady) => {
      if (isReady && window.isWalletReady) {
        window.isWalletReady = () => isReady;
      }
    });
    this.cleanupFunctions.push(walletUnsubscribe);
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
    const gcTimer = setInterval(() => { try { if (window.gc) window.gc(); } catch (_) {} }, CONFIG.SECURITY.CLEANUP_INTERVAL);
    this.timers.push(gcTimer);
    
    const cacheTimer = setInterval(() => { 
      if (!isOperationActive() && window.clearBlockchainCaches) {
        window.clearBlockchainCaches(); 
      }
    }, 600000);
    this.timers.push(cacheTimer);
  }

  setupRefreshLabels() {
    const setRefreshLabels = () => {
      try {
        const t = getTranslation('import_section.refresh_button', 'Refresh');
        
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

    document.addEventListener('DOMContentLoaded', setRefreshLabels);
    
    if (window.i18next && typeof window.i18next.on === 'function') {
      window.i18next.on('languageChanged', setRefreshLabels);
    }
    
    setTimeout(setRefreshLabels, 100);
  }

  // === READY STATE ===
  markAsReady() {
    appInitialized = true;
    appState.set('initialized', true);
    const initTime = Date.now() - this.initStartTime;
    
    const loadingOverlay = document.getElementById('initialLoadingOverlay');
    if (loadingOverlay) {
      loadingOverlay.style.opacity = '0';
      loadingOverlay.style.transition = 'opacity 0.3s ease';
      setTimeout(() => {
        loadingOverlay.style.display = 'none';
      }, 300);
    }
    
    eventBus.emit(EVENTS.SYSTEM_READY, { initTime, version: VERSION.STRING, timestamp: Date.now() });
    window.dispatchEvent(new CustomEvent('nitoWalletReady', { detail: { initTime, version: VERSION.STRING } }));
    
    const readyMessage = getTranslation('system.wallet_ready', 
      `NITO Wallet ready in ${initTime}ms - Version ${VERSION.STRING}`, 
      { time: initTime, version: VERSION.STRING }
    );
    console.log(readyMessage);
    
    if (FEATURE_FLAGS.LOG_ADDRESSES && window.isWalletReady && window.isWalletReady()) {
      this.logWalletAddresses();
    }
  }

  logWalletAddresses() {
    try {
      const addresses = appState.get('addresses') || {
        bech32: window.getWalletAddress ? window.getWalletAddress() : '',
        taproot: window.getTaprootAddress ? window.getTaprootAddress() : '',
        legacy: window.legacyAddress || '',
        p2sh: window.p2shAddress || ''
      };
      
      console.log('=== WALLET ADDRESSES ===');
      console.log('Bech32:', addresses.bech32);
      console.log('Bech32m (Taproot):', addresses.taproot);
      console.log('Legacy:', addresses.legacy);
      console.log('P2SH:', addresses.p2sh);
      console.log('========================');
    } catch (error) {}
  }

  // === ERROR HANDLING ===
  async handleInitializationError(error) {
    const errorMessage = getTranslation('errors.initialization_failed',
      'Application initialization failed. Please refresh the page.');
      
    try {
      const body = document.body;
      const div = document.createElement('div');
      div.style.cssText = `
        position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
        background: #ff4444; color: white; padding: 20px; border-radius: 8px;
        z-index: 10000; text-align: center; max-width: 90%;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
      `;
      
      const title = getTranslation('system.initialization_error_title', 'Initialization Error');
      const reloadText = getTranslation('system.reload_page', 'Reload page');
      const errorDetails = getTranslation('errors.error_details', 'Error');
      
      div.innerHTML = `
        <h3>${title}</h3>
        <p>${errorMessage}</p>
        <p style="font-size: 0.9em; opacity: 0.8; margin-top: 10px;">${errorDetails}: ${error.message}</p>
        <button onclick="location.reload()" style="
          margin-top: 15px; padding: 10px 20px; background: white; 
          color: #ff4444; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;">
          ${reloadText}
        </button>
      `;
      body.appendChild(div);
      setTimeout(() => { location.reload(); }, 10000);
    } catch (_) {
      const errorDetails = getTranslation('errors.error_details', 'Error');
      alert(errorMessage + '\n\n' + errorDetails + ': ' + error.message);
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

  // === CLEANUP ===
  destroy() {
    this.timers.forEach(timer => clearInterval(timer));
    this.timers = [];
    
    this.cleanupFunctions.forEach(cleanup => {
      try {
        cleanup();
      } catch (error) {
        console.error('[APP] Cleanup error:', error);
      }
    });
    this.cleanupFunctions = [];
    
    appState.reset();
  }

  // === STATUS ===
  static getStatus() {
    return {
      initialized: appInitialized,
      librariesReady: areLibrariesReady(),
      version: VERSION.STRING,
      state: appState.state,
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

// === DEPENDENCY MANAGER ===
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

// === INITIALIZATION ===
let appInitialized = false;
let initializationPromise = null;

const initializeApp = async () => {
  try {
    await NITOWalletApp.initialize();
  } catch (error) {
    console.error('[APP] Auto-initialization failed:', error);
  }
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeApp);
} else {
  setTimeout(initializeApp, 100);
}

// === GLOBAL EXPORTS ===
if (typeof window !== 'undefined') {
  window.NITOWalletApp = NITOWalletApp;
  window.initializeApp = initializeApp;
  window.startOperation = startOperation;
  window.endOperation = endOperation;
  window.isOperationActive = isOperationActive;
  window.appState = appState;
  window.getAppState = () => appState.state;
}

export default NITOWalletApp;