// Security Layer for NITO Wallet
// Handles encryption, key management, validation

import { SECURITY_CONFIG, VALIDATION_PATTERNS, ELEMENT_IDS, ERROR_CODES, FEATURE_FLAGS, getTranslation } from './config.js';
import { eventBus, EVENTS } from './events.js';

// === TIMER RECURSION PROTECTION ===
let timerUpdateInProgress = false;
let lastTimerUpdate = 0;
const TIMER_COOLDOWN = 100;

// === TIMER CONTEXT MANAGEMENT ===
class TimerContext {
  constructor() {
    this.context = null;
    this.callbacks = new Map();
  }

  setContext(context, callback = null) {
    this.context = context;
    if (callback) {
      this.callbacks.set(context, callback);
    }
  }

  clearContext() {
    this.context = null;
  }

  executeCallback() {
    const callback = this.callbacks.get(this.context);
    if (callback && typeof callback === 'function') {
      try {
        callback();
      } catch (error) {
        console.warn('Timer callback execution failed:', error);
      }
    }
  }

  hasContext(context) {
    return this.context === context;
  }
}

// === ENHANCED SECURE KEY MANAGER ===
class SecureKeyManager {
  constructor() {
    this.sessionKey = null;
    this.encryptedData = new Map();
    this.lastAccess = Date.now();
    this.cleanupTimer = null;
    this.inactivityTimer = null;
    this.displayTimer = null;
    this.operationCheckTimer = null;
    this.lastClearReason = null;
    this.isInactivityActive = false;
    this.reloadTimer = null;
    
    this.generationTimer = null;
    this.generationStartTime = null;

    this.setupAutoCleanup();
    this.setupPageHideCleanup();
    this.setupInactivityTimer();
    this.setupOperationMonitoring();
  }

  async generateSessionKey() {
    if (!this.sessionKey) {
      const keyMaterial = crypto.getRandomValues(new Uint8Array(32));
      this.sessionKey = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
      );
    }
    return this.sessionKey;
  }

  async encrypt(data) {
    try {
      const key = await this.generateSessionKey();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(JSON.stringify(data));
      const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
      return { iv, data: new Uint8Array(encrypted) };
    } catch (error) {
      console.error('Encryption failed:', error);
      const errorMsg = getTranslation('security.failed_to_encrypt', 'Failed to encrypt sensitive data');
      throw new Error(errorMsg);
    }
  }

  async decrypt(encryptedData) {
    try {
      const key = await this.generateSessionKey();
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: encryptedData.iv },
        key,
        encryptedData.data
      );
      const decoded = new TextDecoder().decode(decrypted);
      return JSON.parse(decoded);
    } catch (error) {
      console.error('Decryption failed:', error);
      throw new Error('Failed to decrypt sensitive data');
    }
  }

  async storeKey(id, keyData) {
    try {
      this.updateAccess();

      if (this.encryptedData.size >= SECURITY_CONFIG.MAX_MEMORY_KEYS) {
        this.clearOldestKeys(1);
      }

      const encrypted = await this.encrypt(keyData);
      this.encryptedData.set(id, {
        ...encrypted,
        timestamp: Date.now()
      });

    } catch (error) {
      console.error(`Failed to store key ${id}:`, error);
      throw error;
    }
  }

  async getKey(id) {
    try {
      this.updateAccess();
      const encrypted = this.encryptedData.get(id);
      if (!encrypted) return null;

      return await this.decrypt(encrypted);
    } catch (error) {
      console.error(`Failed to retrieve key ${id}:`, error);
      return null;
    }
  }

  hasKey(id) {
    return this.encryptedData.has(id);
  }

  clearOldestKeys(count = 1) {
    const entries = Array.from(this.encryptedData.entries())
      .sort((a, b) => a[1].timestamp - b[1].timestamp)
      .slice(0, count);

    entries.forEach(([id]) => {
      this.encryptedData.delete(id);
    });
  }

  isOperationInProgress() {
    if (typeof window !== 'undefined' && window.isOperationActive) {
      return window.isOperationActive();
    }
    return false;
  }

  isWalletOperationInProgress() {
    if (typeof window !== 'undefined' && window.isOperationActive) {
      return window.isOperationActive('import') ||
             window.isOperationActive('wallet-import') ||
             window.isOperationActive('email-connect') ||
             window.isOperationActive('generation') ||
             window.isOperationActive('connection');
    }
    return false;
  }

  startGenerationTimer() {
    this.generationStartTime = Date.now();
    
    if (this.generationTimer) {
      clearTimeout(this.generationTimer);
    }
    
    this.generationTimer = setTimeout(() => {
      this.clearGeneratedKeys();
    }, SECURITY_CONFIG.GENERATION_KEY_TIMEOUT || 600000);
    
    this.startGenerationTimerDisplay();
  }
  
  startGenerationTimerDisplay() {
    const updateGenerationTimer = () => {
      const timerElement = document.getElementById('inactivityTimer');
      if (!timerElement || !this.generationStartTime) return;
      
      const now = Date.now();
      const elapsed = now - this.generationStartTime;
      const remaining = Math.max(0, (SECURITY_CONFIG.GENERATION_KEY_TIMEOUT || 600000) - elapsed);
      
      const minutes = Math.floor(remaining / 60000);
      const seconds = Math.floor((remaining % 60000) / 1000);
      
      timerElement.textContent = `[${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}]`;
      
      if (remaining > 0) {
        requestAnimationFrame(updateGenerationTimer);
      }
    };
    
    updateGenerationTimer();
  }
  
  clearGeneratedKeys() {
    const generatedElements = [
      'hdMasterKey',
      'mnemonicPhrase',
      'generatedAddress'
    ];
    
    generatedElements.forEach(id => {
      const element = document.getElementById(id);
      if (element) {
        element.textContent = '';
        element.classList.add('blurred');
      }
    });
    
    if (this.generationTimer) {
      clearTimeout(this.generationTimer);
      this.generationTimer = null;
    }
    this.generationStartTime = null;
  }

  clearAll(reason = 'unknown') {
    try {
      this.lastClearReason = reason;
      console.log(`[SECURITY] All secure keys cleared (reason: ${reason})`);

      this.encryptedData.clear();
      this.sessionKey = null;

      if (this.cleanupTimer) {
        clearTimeout(this.cleanupTimer);
        this.cleanupTimer = null;
      }

      if (reason === 'inactivity_timeout' || reason === 'session_timeout') {
        if (this.inactivityTimer) {
          clearTimeout(this.inactivityTimer);
          this.inactivityTimer = null;
        }
        this.isInactivityActive = false;
      }

      if (this.displayTimer) {
        clearInterval(this.displayTimer);
        this.displayTimer = null;
      }

      if (this.operationCheckTimer) {
        clearInterval(this.operationCheckTimer);
        this.operationCheckTimer = null;
      }

      eventBus.emit(EVENTS.KEYS_CLEARED, { reason });

    } catch (error) {
      console.error('Error clearing keys:', error);
    }
  }

  executeAutoReload() {
    const isDarkMode = document.body.getAttribute('data-theme') === 'dark';
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

    const title = (window.i18next && window.i18next.isInitialized) 
      ? getTranslation('security.session_expired_title', 'Session expired')
      : 'Session expired';
    const message = (window.i18next && window.i18next.isInitialized)
      ? getTranslation('security.auto_reload_message', 'Reloading...')
      : 'Reloading...';

    overlay.innerHTML = `
      <div style="
        background: ${isDarkMode ? '#1a202c' : '#ffffff'};
        color: ${isDarkMode ? '#e2e8f0' : '#111111'};
        padding: 2rem;
        border-radius: 16px;
        text-align: center;
        box-shadow: 0 20px 50px rgba(0,0,0,0.5);
        border: 2px solid ${isDarkMode ? '#4a5568' : '#e2e8f0'};
      ">
        <div style="font-size: 3rem; margin-bottom: 1rem;">🔒</div>
        <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem;">${title}</div>
        <div style="opacity: 0.8;">${message}</div>
      </div>
    `;

    document.body.appendChild(overlay);

    setTimeout(() => {
      window.location.reload();
    }, 2000);
  }

  setupOperationMonitoring() {
    this.operationCheckTimer = setInterval(() => {
    }, 5000);
  }

  updateAccess() {
    const now = Date.now();
    this.lastAccess = now;
    this.resetInactivityTimer();
  }

  setupAutoCleanup() {
    if (this.cleanupTimer) clearTimeout(this.cleanupTimer);
    
    this.cleanupTimer = setTimeout(() => {
      if (this.isOperationInProgress() || this.isWalletOperationInProgress()) {
        this.setupAutoCleanup();
        return;
      }
      
      this.clearAll('session_timeout');
    }, SECURITY_CONFIG.SESSION_TIMEOUT);
  }

  setupPageHideCleanup() {
    const cleanup = () => {
      this.clearSensitiveDisplayOnly('page_unload');
      this.clearSensitiveFields();
    };

    window.addEventListener('pagehide', cleanup);
    window.addEventListener('beforeunload', cleanup);
  }

  setupInactivityTimer() {
    this.isInactivityActive = true;
    this.resetInactivityTimer();
    this.startTimerDisplay();
  }

  resetInactivityTimer() {
    if (this.inactivityTimer) {
      clearTimeout(this.inactivityTimer);
      this.inactivityTimer = null;
    }
    
    if (this.reloadTimer) {
      clearTimeout(this.reloadTimer);
      this.reloadTimer = null;
    }

    this.inactivityTimer = setTimeout(() => {
      if (this.isOperationInProgress() || this.isWalletOperationInProgress()) {
        this.lastAccess = Date.now();
        this.resetInactivityTimer();
        return;
      }
      
      this.clearSensitiveData('inactivity_timeout');
      eventBus.emit(EVENTS.SESSION_EXPIRED, { reason: 'inactivity' });
      
      if (FEATURE_FLAGS.AUTO_RELOAD_ON_KEY_CLEAR) {
        this.reloadTimer = setTimeout(() => {
          if (!this.isOperationInProgress() && !this.isWalletOperationInProgress()) {
            this.executeAutoReload();
          }
        }, 10000);
      }
    }, SECURITY_CONFIG.INACTIVITY_TIMEOUT);

    this.isInactivityActive = true;
  }

  startTimerDisplay() {
    if (this.displayTimer) {
      clearInterval(this.displayTimer);
    }

    this.displayTimer = setInterval(() => {
      this.updateTimerDisplay();
    }, 1000);
  }

  updateTimerDisplay() {
    const timerElement = document.getElementById(ELEMENT_IDS.INACTIVITY_TIMER);
    if (!timerElement || this.generationStartTime) return;

    const now = Date.now();
    const elapsed = now - this.lastAccess;
    const remaining = Math.max(0, SECURITY_CONFIG.INACTIVITY_TIMEOUT - elapsed);

    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);

    if (!this.generationStartTime) {
      timerElement.textContent = `[${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}]`;
    }

    if (remaining <= 0 && this.isInactivityActive) {
      clearInterval(this.displayTimer);
      this.displayTimer = null;
    }
  }

  clearSensitiveData(reason = 'inactivity') {
    const sensitiveElements = [
      ELEMENT_IDS.HD_MASTER_KEY,
      ELEMENT_IDS.MNEMONIC_PHRASE,
      ELEMENT_IDS.GENERATED_ADDRESS,
      'privateKey',
      'privateKeyHex'
    ];

    sensitiveElements.forEach(id => {
      const element = document.getElementById(id);
      if (element) {
        element.textContent = '';
        element.classList.add('blurred');
      }
    });

    eventBus.emit(EVENTS.INACTIVITY_WARNING, { reason });
  }

  clearSensitiveDisplayOnly(reason = 'page_unload') {
    const sensitiveElements = [
      ELEMENT_IDS.HD_MASTER_KEY,
      ELEMENT_IDS.MNEMONIC_PHRASE,
      ELEMENT_IDS.GENERATED_ADDRESS,
      'privateKey',
      'privateKeyHex'
    ];

    sensitiveElements.forEach(id => {
      const element = document.getElementById(id);
      if (element) {
        element.textContent = '';
        element.classList.add('blurred');
      }
    });
  }

  clearSensitiveFields() {
    const fieldsToKeep = new Set([ELEMENT_IDS.WALLET_ADDRESS]);

    document.querySelectorAll('input[type="password"], input[type="text"], textarea').forEach(input => {
      if (!fieldsToKeep.has(input.id)) {
        input.value = '';
      }
    });
  }

  updateLastActionTime() {
    const now = Date.now();
    
    if (now - lastTimerUpdate < TIMER_COOLDOWN) {
      return;
    }
    
    lastTimerUpdate = now;
    this.updateAccess();
  }
}

// === GLOBAL INTERACTION TRACKING ===
function setupGlobalInteractionTracking() {
  const interactionEvents = [
    'click',
    'mousedown',
    'touchstart',
    'keydown',
    'scroll',
    'change',
    'input',
    'focus'
  ];
  
  const resetTimer = () => {
    if (keyManager && keyManager.isInactivityActive) {
      keyManager.updateAccess();
    }
  };
  
  interactionEvents.forEach(eventType => {
    document.addEventListener(eventType, resetTimer, { 
      passive: true, 
      capture: true 
    });
  });
  
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      resetTimer();
    }
  });
}

// === CREDENTIAL DERIVATION ===
export async function deriveFromCredentials(email, password, wordCount = 24) {
  try {
    const normalizedEmail = email.trim().toLowerCase();

    if (!validateInput(normalizedEmail, 'email')) {
      const errorMsg = getTranslation('errors.enter_email_password', 'Invalid email format');
      throw new Error(errorMsg);
    }

    if (!password || password.length < 1) {
      const errorMsg = getTranslation('errors.enter_email_password', 'Password cannot be empty');
      throw new Error(errorMsg);
    }

    const encoder = new TextEncoder();
    const salt = encoder.encode('nito-mnemonic:' + normalizedEmail);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const bits = await crypto.subtle.deriveBits({
      name: 'PBKDF2',
      hash: 'SHA-512',
      salt,
      iterations: 200000
    }, keyMaterial, wordCount === 24 ? 256 : 128);

    const entropy = Array.from(new Uint8Array(bits))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    if (!window.bip39) {
      throw new Error('BIP39 library not available');
    }

    return window.bip39.entropyToMnemonic(entropy);
  } catch (error) {
    console.error('Credential derivation failed:', error);
    throw new Error(`Failed to derive credentials: ${error.message}`);
  }
}

// === INPUT VALIDATION ===
export function validateInput(input, type) {
  if (!input || typeof input !== 'string') return false;

  const trimmed = input.trim();
  if (!trimmed) return false;

  try {
    switch (type) {
      case 'wif':
        return VALIDATION_PATTERNS.WIF.test(trimmed);

      case 'hex':
        return VALIDATION_PATTERNS.HEX_PRIVATE_KEY.test(trimmed);

      case 'xprv':
        return VALIDATION_PATTERNS.XPRV.test(trimmed);

      case 'address':
        return VALIDATION_PATTERNS.ADDRESS.test(trimmed);

      case 'bech32':
        return VALIDATION_PATTERNS.BECH32_ADDRESS.test(trimmed);

      case 'bech32m':
        return VALIDATION_PATTERNS.BECH32M_ADDRESS.test(trimmed);

      case 'amount':
        return VALIDATION_PATTERNS.AMOUNT.test(trimmed) && parseFloat(trimmed) > 0;

      case 'mnemonic':
        const words = trimmed.split(/\s+/);
        return [12, 15, 18, 21, 24].includes(words.length) && words.every(word => word.length > 0);

      case 'txid':
        return VALIDATION_PATTERNS.TXID.test(trimmed);

      case 'email':
        return VALIDATION_PATTERNS.EMAIL.test(trimmed);

      case 'scriptHex':
        return VALIDATION_PATTERNS.SCRIPT_HEX.test(trimmed);

      default:
        console.warn(`Unknown validation type: ${type}`);
        return false;
    }
  } catch (error) {
    console.error(`Validation error for type ${type}:`, error);
    return false;
  }
}

// === INPUT TYPE DETECTION ===
export function detectInputType(input) {
  if (!input || typeof input !== 'string') return 'unknown';

  const trimmed = input.trim();

  if (validateInput(trimmed, 'xprv')) return 'xprv';
  if (validateInput(trimmed, 'mnemonic')) return 'mnemonic';
  if (validateInput(trimmed, 'wif')) return 'wif';
  if (validateInput(trimmed, 'hex')) return 'hex';

  return 'unknown';
}

// === RATE LIMITER ===
class RateLimiter {
  constructor() {
    this.attempts = new Map();
  }

  check(key, maxAttempts = SECURITY_CONFIG.RATE_LIMIT_ATTEMPTS, timeWindow = SECURITY_CONFIG.RATE_LIMIT_WINDOW) {
    const now = Date.now();
    const attempts = this.attempts.get(key) || [];

    const recentAttempts = attempts.filter(time => now - time < timeWindow);

    if (recentAttempts.length >= maxAttempts) {
      const oldestAttempt = Math.min(...recentAttempts);
      const waitTime = Math.ceil((timeWindow - (now - oldestAttempt)) / 1000);
      const errorMsg = getTranslation('security.rate_limit_exceeded',
        `Rate limit exceeded. Please wait ${waitTime} seconds before retrying.`,
        { seconds: waitTime }
      );
      throw new Error(errorMsg);
    }

    recentAttempts.push(now);
    this.attempts.set(key, recentAttempts);

    if (this.attempts.size > 100) {
      this.cleanupOldAttempts(now, timeWindow);
    }
  }

  cleanupOldAttempts(now, timeWindow) {
    for (const [key, attempts] of this.attempts) {
      const recentAttempts = attempts.filter(time => now - time < timeWindow);
      if (recentAttempts.length === 0) {
        this.attempts.delete(key);
      } else {
        this.attempts.set(key, recentAttempts);
      }
    }
  }
}

// === REVEAL BUTTON SETUP ===
export function setupRevealButton(buttonId, targetId, timeout = SECURITY_CONFIG.BLUR_TIMEOUT) {
  try {
    const button = document.getElementById(buttonId);
    const target = document.getElementById(targetId);

    if (!button) {
      console.warn(`Reveal button not found: ${buttonId}`);
      return false;
    }

    if (!target) {
      console.warn(`Reveal target not found: ${targetId}`);
      return false;
    }

    const newButton = button.cloneNode(true);
    button.parentNode.replaceChild(newButton, button);

    newButton.addEventListener('click', () => {
      try {
        armInactivityTimerSafely();

        newButton.disabled = true;
        target.classList.remove('blurred');

        setTimeout(() => {
          target.classList.add('blurred');
          newButton.disabled = false;
        }, timeout);
      } catch (error) {
        console.error(`Reveal button error for ${buttonId}:`, error);
        newButton.disabled = false;
      }
    });

    return true;
  } catch (error) {
    console.error(`Failed to setup reveal button ${buttonId}:`, error);
    return false;
  }
}

// === TIMER MANAGEMENT ===
const timerContext = new TimerContext();

export function armInactivityTimerSafely() {
  try {
    if (timerUpdateInProgress) {
      return;
    }
    
    const now = Date.now();
    if (now - lastTimerUpdate < TIMER_COOLDOWN) {
      return;
    }
    
    timerUpdateInProgress = true;
    
    try {
      if (keyManager && typeof keyManager.updateLastActionTime === 'function') {
        keyManager.updateLastActionTime();
      }
    } finally {
      timerUpdateInProgress = false;
    }
    
  } catch (error) {
    console.warn('Timer arm failed:', error);
    timerUpdateInProgress = false;
  }
}

export function setTimerContext(context, callback = null) {
  timerContext.setContext(context, callback);
}

export function clearTimerContext() {
  timerContext.clearContext();
}

// === INACTIVITY TIMER FOR WALLET ===
export function updateInactivityTimer() {
  if (!keyManager) return;
  
  keyManager.updateLastActionTime();
  
  const timerElement = document.getElementById(ELEMENT_IDS.INACTIVITY_TIMER);
  if (!timerElement) return;

  if (keyManager.displayTimer) {
    clearInterval(keyManager.displayTimer);
  }

  const updateTimerDisplay = () => {
    const now = Date.now();
    const elapsed = now - keyManager.lastAccess;
    const remaining = Math.max(0, SECURITY_CONFIG.INACTIVITY_TIMEOUT - elapsed);
    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    
    if (!keyManager.generationStartTime) {
      timerElement.textContent = `[${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}]`;
    }
    
    if (remaining <= 0) {
      clearInterval(keyManager.displayTimer);
    }
  };

  updateTimerDisplay();
  keyManager.displayTimer = setInterval(updateTimerDisplay, 1000);
}

// === GLOBAL INSTANCES ===
export const keyManager = new SecureKeyManager();
export const rateLimiter = new RateLimiter();

// === INITIALIZATION ===
if (typeof window !== 'undefined') {
  setupGlobalInteractionTracking();
}

// === EVENT LISTENERS ===
eventBus.on(EVENTS.KEYS_CLEARED, (data) => {
});

eventBus.on(EVENTS.SESSION_EXPIRED, (data) => {
  const warningMsg = getTranslation('security.session_timeout_warning',
    'Session expired due to inactivity. Wallet will reload automatically.');

  if (window.showNotification) {
    window.showNotification(warningMsg, 'warning');
  }
});

// === GLOBAL COMPATIBILITY ===
if (typeof window !== 'undefined') {
  window.armInactivityTimerSafely = armInactivityTimerSafely;
  window.updateInactivityTimer = updateInactivityTimer;
  window.keyManager = keyManager;
}

// === INITIALIZATION ===
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    setupRevealButton(ELEMENT_IDS.REVEAL_HD_KEY, ELEMENT_IDS.HD_MASTER_KEY);
    setupRevealButton(ELEMENT_IDS.REVEAL_MNEMONIC, ELEMENT_IDS.MNEMONIC_PHRASE);
  });
} else {
  setupRevealButton(ELEMENT_IDS.REVEAL_HD_KEY, ELEMENT_IDS.HD_MASTER_KEY);
  setupRevealButton(ELEMENT_IDS.REVEAL_MNEMONIC, ELEMENT_IDS.MNEMONIC_PHRASE);
}