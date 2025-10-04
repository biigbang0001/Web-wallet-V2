import { SECURITY_CONFIG, FEATURE_FLAGS, ERROR_CODES, getTranslation } from './config.js';
import { eventBus, EVENTS } from './events.js';
import { memoryEncryption } from './encryption.js';

// === RATE LIMITER ===
class RateLimiter {
  constructor() {
    this.attempts = new Map();
    this.maxMapSize = 1000;
  }

  check(key, maxAttempts, windowMs) {
    const now = Date.now();
    
    if (this.attempts.size > this.maxMapSize) {
      this.cleanup();
    }
    
    if (!this.attempts.has(key)) {
      this.attempts.set(key, []);
    }
    
    const attempts = this.attempts.get(key);
    const recentAttempts = attempts.filter(timestamp => now - timestamp < windowMs);
    
    if (recentAttempts.length >= maxAttempts) {
      const oldestAttempt = recentAttempts[0];
      const waitTime = Math.ceil((windowMs - (now - oldestAttempt)) / 1000);
      throw new Error(getTranslation('security.rate_limit_exceeded', 
        'Rate limit exceeded. Please wait {{seconds}} seconds before retrying.', 
        { seconds: waitTime }
      ));
    }
    
    recentAttempts.push(now);
    this.attempts.set(key, recentAttempts);
    
    return recentAttempts.length;
  }

  reset(key) {
    this.attempts.delete(key);
  }

  cleanup() {
    const now = Date.now();
    const maxAge = 600000;
    
    for (const [key, attempts] of this.attempts.entries()) {
      const recentAttempts = attempts.filter(timestamp => now - timestamp < maxAge);
      if (recentAttempts.length === 0) {
        this.attempts.delete(key);
      } else {
        this.attempts.set(key, recentAttempts);
      }
    }
    
    if (this.attempts.size > this.maxMapSize) {
      const sortedEntries = Array.from(this.attempts.entries())
        .sort((a, b) => Math.max(...b[1]) - Math.max(...a[1]));
      
      this.attempts = new Map(sortedEntries.slice(0, Math.floor(this.maxMapSize / 2)));
    }
  }
}

export const rateLimiter = new RateLimiter();

setInterval(() => rateLimiter.cleanup(), 300000);

// === INPUT VALIDATION ===
export function validateInput(value, type) {
  if (!value || typeof value !== 'string') {
    throw new Error(getTranslation('security.empty_input', 'Empty input provided'));
  }

  switch (type) {
    case 'email':
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(value)) {
        throw new Error(getTranslation('security.invalid_email_format', 'Invalid email format'));
      }
      return true;

    case 'wif':
      const wifRegex = /^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$/;
      if (!wifRegex.test(value)) {
        throw new Error(getTranslation('security.invalid_wif_format', 'Invalid WIF format'));
      }
      return true;

    case 'hex':
      const hexRegex = /^[0-9a-fA-F]{64}$/;
      if (!hexRegex.test(value)) {
        throw new Error(getTranslation('security.invalid_hex_format', 'Invalid hex format - must contain 64 characters'));
      }
      return true;

    case 'xprv':
      if (!value.startsWith('xprv')) {
        throw new Error(getTranslation('wallet.invalid_seed_xprv', 'Invalid seed or XPRV'));
      }
      return true;

    case 'mnemonic':
      const words = value.trim().split(/\s+/);
      if (words.length !== 12 && words.length !== 24) {
        throw new Error(getTranslation('wallet.invalid_mnemonic', 'Invalid mnemonic phrase - must be 12 or 24 words'));
      }
      if (window.bip39 && !window.bip39.validateMnemonic(value)) {
        throw new Error(getTranslation('wallet.invalid_mnemonic', 'Invalid mnemonic phrase'));
      }
      return true;

    default:
      throw new Error(getTranslation('security.unknown_validation_type', 'Unknown validation type: {{type}}', { type }));
  }
}

// === KEY MANAGER ===
export class KeyManager {
  constructor() {
    this.keys = new Map();
    this.maxKeys = SECURITY_CONFIG.MAX_MEMORY_KEYS;
    this.lastAccess = Date.now();
    this.sessionTimeout = SECURITY_CONFIG.SESSION_TIMEOUT;
    this.inactivityTimeout = SECURITY_CONFIG.INACTIVITY_TIMEOUT;
    this.isInactivityActive = false;
    this.inactivityTimer = null;
    this.timerUpdateInterval = null;
    this.remainingTime = 600000;
    this.blurTimer = null;
    this.blurTimestamp = null;
    this.sessionTimer = null;
    this.cleanupInterval = null;
    this.encryptionInitialized = false;
    this.initializationPromise = null;
    this.activeKeyUsage = new Map();
  }

  async ensureInitialized() {
    if (this.encryptionInitialized) return;
    
    if (this.initializationPromise) {
      return this.initializationPromise;
    }
    
    this.initializationPromise = (async () => {
      await memoryEncryption.initialize();
      this.encryptionInitialized = true;
    })();
    
    return this.initializationPromise;
  }

  async initializeTimers() {
    await this.ensureInitialized();

    this.resetInactivityTimer();
    
    this.sessionTimer = setTimeout(() => {
      this.clearSensitiveData('session_timeout');
    }, this.sessionTimeout);

    this.cleanupInterval = setInterval(() => {
      this.cleanupOldKeys();
    }, SECURITY_CONFIG.CLEANUP_INTERVAL);

    if (typeof window !== 'undefined') {
      window.addEventListener('blur', () => this.handleWindowBlur());
      window.addEventListener('focus', () => this.handleWindowFocus());
      
      const activityEvents = ['mousedown', 'keydown', 'scroll', 'touchstart', 'click'];
      
      activityEvents.forEach(eventType => {
        document.addEventListener(eventType, () => {
          this.updateAccess();
        }, { passive: true, capture: true });
      });
    }

    eventBus.on(EVENTS.TIMER_ARM_REQUEST, () => {
      this.updateAccess();
    });
  }

  updateTimerDisplay() {
    const timerElement = document.getElementById('inactivityTimer');
    if (!timerElement) return;

    const minutes = Math.floor(this.remainingTime / 60000);
    const seconds = Math.floor((this.remainingTime % 60000) / 1000);
    timerElement.textContent = `[${minutes}:${seconds.toString().padStart(2, '0')}]`;
  }

  async storeKey(id, value, metadata = {}) {
    await this.ensureInitialized();
    
    if (this.keys.size >= this.maxKeys) {
      const oldestKey = Array.from(this.keys.entries())
        .sort((a, b) => a[1].timestamp - b[1].timestamp)[0];
      await this.deleteKey(oldestKey[0]);
    }

    const encryptedValue = await this.encryptValue(value);
    
    this.keys.set(id, {
      value: encryptedValue,
      timestamp: Date.now(),
      lastAccess: Date.now(),
      metadata
    });

    this.updateAccess();
  }

  async retrieveKey(id) {
    await this.ensureInitialized();
    
    const keyData = this.keys.get(id);
    if (!keyData) return null;

    keyData.lastAccess = Date.now();
    this.updateAccess();

    const usageId = `${id}_${Date.now()}`;
    this.activeKeyUsage.set(usageId, Date.now());
    
    if (id === 'private_key' || id === 'hd_xprv' || id === 'mnemonic') {
      console.log(`[SECURITY] Sensitive key '${id}' accessed at ${new Date().toISOString()}`);
    }

    const decryptedValue = await this.decryptValue(keyData.value);
    
    setTimeout(() => {
      this.activeKeyUsage.delete(usageId);
      if (typeof window !== 'undefined' && window.gc) {
        try { window.gc(); } catch(e) {}
      }
    }, 5000);

    return decryptedValue;
  }

  async deleteKey(id) {
    const keyData = this.keys.get(id);
    if (keyData && keyData.value instanceof Uint8Array) {
      keyData.value.fill(0);
    }
    this.keys.delete(id);
  }

  async encryptValue(value) {
    await this.ensureInitialized();
    
    try {
      if (typeof value === 'string') {
        return await memoryEncryption.encryptString(value);
      } else if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
        return await memoryEncryption.encrypt(value);
      }
      
      const jsonString = JSON.stringify(value);
      return await memoryEncryption.encryptString(jsonString);
    } catch (error) {
      console.error(`[SECURITY] ${getTranslation('security.failed_to_encrypt', 'Failed to encrypt sensitive data')}:`, error);
      throw error;
    }
  }

  async decryptValue(encryptedValue) {
    await this.ensureInitialized();
    
    try {
      if (typeof encryptedValue === 'string') {
        return await memoryEncryption.decryptString(encryptedValue);
      } else {
        const decrypted = await memoryEncryption.decrypt(encryptedValue);
        return new TextDecoder().decode(decrypted);
      }
    } catch (error) {
      console.error(`[SECURITY] ${getTranslation('security.failed_to_decrypt', 'Failed to decrypt data')}:`, error);
      throw error;
    }
  }

  updateAccess() {
    this.lastAccess = Date.now();
    
    if (this.sessionTimer) {
      clearTimeout(this.sessionTimer);
      this.sessionTimer = setTimeout(() => {
        this.clearSensitiveData('session_timeout');
      }, this.sessionTimeout);
    }

    this.resetInactivityTimer();
  }

  handleWindowBlur() {
    this.blurTimestamp = Date.now();
    
    this.blurTimer = setTimeout(() => {
      if (!this.isOperationInProgress() && !this.isWalletOperationInProgress()) {
        this.clearSensitiveData('window_blur');
      }
    }, SECURITY_CONFIG.BLUR_TIMEOUT);
  }

  handleWindowFocus() {
    if (this.blurTimer) {
      clearTimeout(this.blurTimer);
      this.blurTimer = null;
    }

    if (this.blurTimestamp) {
      const blurDuration = Date.now() - this.blurTimestamp;
      if (blurDuration > SECURITY_CONFIG.BLUR_TIMEOUT) {
        this.clearSensitiveData('long_blur');
      }
      this.blurTimestamp = null;
    }

    this.updateAccess();
  }

  resetInactivityTimer() {
    if (this.inactivityTimer) {
      clearTimeout(this.inactivityTimer);
      this.inactivityTimer = null;
    }
    
    if (this.timerUpdateInterval) {
      clearInterval(this.timerUpdateInterval);
      this.timerUpdateInterval = null;
    }

    this.remainingTime = 600000;
    this.updateTimerDisplay();

    this.timerUpdateInterval = setInterval(() => {
      if (this.isOperationInProgress()) {
        this.remainingTime = 600000;
        this.updateTimerDisplay();
        return;
      }

      this.remainingTime -= 1000;
      
      if (this.remainingTime <= 0) {
        clearInterval(this.timerUpdateInterval);
        this.timerUpdateInterval = null;
      }
      
      this.updateTimerDisplay();
    }, 1000);

    this.inactivityTimer = setTimeout(() => {
      if (this.isOperationInProgress() || this.isWalletOperationInProgress()) {
        console.warn(`[SECURITY] ${getTranslation('security.inactivity_detected', 'Inactivity detected')}`);
        this.resetInactivityTimer();
        return;
      }
      
      this.clearSensitiveData('inactivity_timeout');
      eventBus.emit(EVENTS.SESSION_EXPIRED, { reason: 'inactivity' });
      
      if (FEATURE_FLAGS.AUTO_RELOAD_ON_KEY_CLEAR) {
        setTimeout(() => {
          if (!this.isOperationInProgress() && !this.isWalletOperationInProgress()) {
            this.executeAutoReload();
          }
        }, 10000);
      }
    }, 600000);

    this.isInactivityActive = true;
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
        <div style="font-size: 3rem; margin-bottom: 1rem;">🔒</div>
        <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem;">${sessionExpiredText}</div>
        <div style="opacity: 0.8;">${reloadingText}</div>
      </div>
    `;
    
    document.body.appendChild(overlay);
    
    setTimeout(() => {
      window.location.reload();
    }, 2000);
  }

  isOperationInProgress() {
    if (typeof window !== 'undefined' && window.isOperationActive) {
      return window.isOperationActive();
    }
    return false;
  }

  isWalletOperationInProgress() {
    if (typeof window !== 'undefined') {
      const hasWalletKeys = this.keys.size > 0 || 
                           window.hdManager?.hdWallet || 
                           (window.keyPairs && window.keyPairs.size > 0);
      return hasWalletKeys && this.isOperationInProgress();
    }
    return false;
  }

  async clearSensitiveData(reason = 'manual') {
    console.log(`[SECURITY] ${getTranslation('loading.cache_clearing', 'Clearing caches...')} (${reason})`);

    this.activeKeyUsage.clear();

    const sensitiveKeys = ['mnemonic', 'hd_xprv', 'private_key', 'public_key'];
    for (const keyId of sensitiveKeys) {
      await this.deleteKey(keyId);
    }

    for (const [id, keyData] of this.keys.entries()) {
      if (keyData.value instanceof Uint8Array) {
        keyData.value.fill(0);
      }
    }
    this.keys.clear();

    if (typeof window !== 'undefined') {
      if (window.hdManager) {
        if (window.hdManager.publicKeyCache) {
          window.hdManager.publicKeyCache.clear();
        }
        window.hdManager = null;
      }
      if (window.keyPairs) {
        window.keyPairs.clear();
      }

      const sensitiveElements = [
        'hdMasterKey', 'mnemonicPhrase', 'privateKeyWIF',
        'emailInput', 'passwordInput', 'signedTx'
      ];

      sensitiveElements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
          if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
            element.value = '';
          } else {
            element.textContent = '';
          }
        }
      });
      
      if (window.gc) {
        try { window.gc(); } catch(e) {}
      }
    }

    if (this.timerUpdateInterval) {
      clearInterval(this.timerUpdateInterval);
      this.timerUpdateInterval = null;
    }

    memoryEncryption.destroy();
    this.encryptionInitialized = false;
    this.initializationPromise = null;

    eventBus.emit(EVENTS.KEYS_CLEARED, { reason, timestamp: Date.now() });

    console.log(`[SECURITY] ${getTranslation('loading.balance_updated', 'Balance updated!')}`);
  }

  async cleanupOldKeys() {
    const now = Date.now();
    const maxAge = 3600000;

    for (const [id, keyData] of this.keys.entries()) {
      if (now - keyData.lastAccess > maxAge) {
        await this.deleteKey(id);
      }
    }
    
    for (const [usageId, timestamp] of this.activeKeyUsage.entries()) {
      if (now - timestamp > 10000) {
        this.activeKeyUsage.delete(usageId);
      }
    }
  }

  async destroy() {
    if (this.inactivityTimer) {
      clearTimeout(this.inactivityTimer);
    }
    if (this.timerUpdateInterval) {
      clearInterval(this.timerUpdateInterval);
    }
    if (this.sessionTimer) {
      clearTimeout(this.sessionTimer);
    }
    if (this.blurTimer) {
      clearTimeout(this.blurTimer);
    }
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    await this.clearSensitiveData('destroy');
  }
}

// === CREDENTIAL DERIVATION ===
export async function deriveFromCredentials(email, password, wordCount = 24) {
  try {
    const normalizedEmail = email.trim().toLowerCase();

    if (!validateInput(normalizedEmail, 'email')) {
      throw new Error(getTranslation('security.invalid_email_format', 'Invalid email format'));
    }

    if (!password || password.length < 1) {
      throw new Error(getTranslation('security.password_cannot_be_empty', 'Password cannot be empty'));
    }

    rateLimiter.check('derive:' + normalizedEmail, 5, 300000);

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
      iterations: SECURITY_CONFIG.PBKDF2_ITERATIONS
    }, keyMaterial, wordCount === 24 ? 256 : 128);

    const entropy = Array.from(new Uint8Array(bits))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    if (!window.bip39) {
      throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library unavailable'));
    }

    return window.bip39.entropyToMnemonic(entropy);
  } catch (error) {
    console.error(`[SECURITY] ${getTranslation('security.failed_to_derive_credentials', 'Failed to derive credentials: {{error}}', {error: error.message})}`);
    throw error;
  }
}

// === ELEMENT VISIBILITY ===
export function revealElement(elementId) {
  const element = document.getElementById(elementId);
  if (!element) {
    throw new Error(getTranslation('security.element_not_found', 'Element not found'));
  }
  element.classList.remove('blurred', 'blurred-input');
}

export function blurElement(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    element.classList.add('blurred');
  }
}

// === UNIFIED CLIPBOARD FUNCTION ===
export async function copyToClipboard(source, options = {}) {
  const { isElementId = false, armTimer = true } = options;
  
  if (armTimer) {
    armInactivityTimerSafely();
  }
  
  let text;
  
  if (isElementId) {
    const element = document.getElementById(source);
    if (!element) {
      throw new Error(getTranslation('security.element_not_found', 'Element not found'));
    }
    
    if (element.classList.contains('blurred')) {
      throw new Error(getTranslation('security.please_reveal_first', 'Please reveal content first'));
    }
    
    text = element.textContent || element.innerText || element.value || '';
  } else {
    text = source;
  }
  
  if (!text || text.trim() === '') {
    throw new Error(getTranslation('security.nothing_to_copy', 'Nothing to copy'));
  }

  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return { success: true, method: 'clipboard-api' };
    } else {
      return await fallbackCopyToClipboard(text);
    }
  } catch (error) {
    console.error(`[SECURITY] ${getTranslation('security.copy_failed', 'Copy failed')}`);
    return await fallbackCopyToClipboard(text);
  }
}

async function fallbackCopyToClipboard(text) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.cssText = 'position:fixed;left:-999999px;top:-999999px;';
  
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  
  try {
    const successful = document.execCommand('copy');
    document.body.removeChild(textarea);
    return { success: successful, method: 'execCommand' };
  } catch (err) {
    document.body.removeChild(textarea);
    throw new Error(getTranslation('security.copy_failed', 'Copy failed'));
  }
}

// === INACTIVITY TIMER ARM ===
export function armInactivityTimerSafely() {
  if (typeof window !== 'undefined' && window.keyManager) {
    try {
      window.keyManager.updateAccess();
    } catch (error) {
      console.warn(`[SECURITY] ${getTranslation('security.timer_arm_failed', 'Failed to arm timer')}`);
    }
  }
}

// === SECURITY INITIALIZATION ===
let keyManagerInstance = null;

export async function initializeSecurity() {
  if (keyManagerInstance) {
    await keyManagerInstance.ensureInitialized();
    
    if (typeof window !== 'undefined' && !window.keyManager) {
      window.keyManager = keyManagerInstance;
    }
    return keyManagerInstance;
  }

  keyManagerInstance = new KeyManager();
  await keyManagerInstance.initializeTimers();
  
  if (typeof window !== 'undefined') {
    window.keyManager = keyManagerInstance;
  }
  
  return keyManagerInstance;
}

// === GLOBAL EXPORTS ===
if (typeof window !== 'undefined') {
  window.armInactivityTimerSafely = armInactivityTimerSafely;
  window.deriveFromCredentials = deriveFromCredentials;
  window.validateInput = validateInput;
  window.revealElement = revealElement;
  window.blurElement = blurElement;
  window.copyToClipboard = copyToClipboard;
  window.rateLimiter = rateLimiter;
  window.initializeSecurity = initializeSecurity;
}

export default KeyManager;