// Security Layer for NITO Wallet
// Handles encryption, key management, validation, and security timers

import { SECURITY_CONFIG, VALIDATION_PATTERNS, ELEMENT_IDS, ERROR_CODES } from './config.js';
import { eventBus, EVENTS } from './events.js';

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

// === SECURE KEY MANAGER ===
class SecureKeyManager {
  constructor() {
    this.sessionKey = null;
    this.encryptedData = new Map();
    this.lastAccess = Date.now();
    this.cleanupTimer = null;
    this.inactivityTimer = null;
    this.displayTimer = null;
    
    this.setupAutoCleanup();
    this.setupPageHideCleanup();
    this.setupInactivityTimer();
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
      throw new Error('Failed to encrypt sensitive data');
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
        console.warn('Maximum key storage exceeded, clearing oldest keys');
        this.clearOldestKeys(1);
      }
      
      const encrypted = await this.encrypt(keyData);
      this.encryptedData.set(id, {
        ...encrypted,
        timestamp: Date.now()
      });
      
      console.log(`Secure key stored: ${id}`);
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
      console.log(`Cleared old key: ${id}`);
    });
  }

  clearAll() {
    try {
      this.encryptedData.clear();
      this.sessionKey = null;
      
      if (this.cleanupTimer) {
        clearTimeout(this.cleanupTimer);
        this.cleanupTimer = null;
      }
      
      if (this.inactivityTimer) {
        clearTimeout(this.inactivityTimer);
        this.inactivityTimer = null;
      }
      
      if (this.displayTimer) {
        clearInterval(this.displayTimer);
        this.displayTimer = null;
      }
      
      console.log('All secure keys cleared');
      eventBus.emit(EVENTS.KEYS_CLEARED);
    } catch (error) {
      console.error('Error clearing keys:', error);
    }
  }

  updateAccess() {
    this.lastAccess = Date.now();
    this.resetInactivityTimer();
  }

  setupAutoCleanup() {
    if (this.cleanupTimer) clearTimeout(this.cleanupTimer);
    this.cleanupTimer = setTimeout(() => {
      this.clearAll();
    }, SECURITY_CONFIG.SESSION_TIMEOUT);
  }

  setupPageHideCleanup() {
    const cleanup = () => {
      this.clearAll();
      this.clearSensitiveFields();
    };
    
    window.addEventListener('pagehide', cleanup);
    window.addEventListener('beforeunload', cleanup);
  }

  setupInactivityTimer() {
    this.resetInactivityTimer();
    this.startTimerDisplay();
  }

  resetInactivityTimer() {
    if (this.inactivityTimer) {
      clearTimeout(this.inactivityTimer);
    }
    
    this.inactivityTimer = setTimeout(() => {
      this.clearSensitiveData();
      eventBus.emit(EVENTS.SESSION_EXPIRED);
    }, SECURITY_CONFIG.INACTIVITY_TIMEOUT);
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
    if (!timerElement) return;

    const now = Date.now();
    const elapsed = now - this.lastAccess;
    const remaining = Math.max(0, SECURITY_CONFIG.INACTIVITY_TIMEOUT - elapsed);
    
    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    
    timerElement.textContent = `[${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}]`;
    
    if (remaining <= 0) {
      clearInterval(this.displayTimer);
    }
  }

  clearSensitiveData() {
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
      }
    });

    console.log('Generated keys cleared, imported wallet preserved');
    eventBus.emit(EVENTS.INACTIVITY_WARNING);
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
    this.updateAccess();
  }
}

// === CREDENTIAL DERIVATION ===
export async function deriveFromCredentials(email, password, wordCount = 24) {
  try {
    const normalizedEmail = email.trim().toLowerCase();
    
    if (!validateInput(normalizedEmail, 'email')) {
      throw new Error('Invalid email format');
    }
    
    if (!password || password.length < 1) {
      throw new Error('Password cannot be empty');
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
      throw new Error(`Rate limit exceeded. Please wait ${waitTime} seconds before trying again.`);
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

// === UTILITY FUNCTIONS ===
export function generateSecureRandom(length = 32) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

export async function secureHash(data, algorithm = 'SHA-256') {
  try {
    const encoder = new TextEncoder();
    const buffer = typeof data === 'string' ? encoder.encode(data) : data;
    const hashBuffer = await crypto.subtle.digest(algorithm, buffer);
    return new Uint8Array(hashBuffer);
  } catch (error) {
    console.error('Hash generation failed:', error);
    throw new Error(`Failed to generate hash: ${error.message}`);
  }
}

// === CLIPBOARD OPERATIONS ===
export function copyToClipboard(elementId) {
  try {
    const sensitiveIds = new Set([
      ELEMENT_IDS.HD_MASTER_KEY,
      ELEMENT_IDS.MNEMONIC_PHRASE,
      'generatedBech32Address',
      'generatedTaprootAddress',
      'privateKey',
      'privateKeyHex'
    ]);
    
    if (sensitiveIds.has(elementId)) {
      armInactivityTimerSafely();
    }

    const element = document.getElementById(elementId);
    if (!element) {
      throw new Error('Element not found');
    }

    if (element.classList.contains('blurred')) {
      throw new Error('Please reveal the content first');
    }

    const text = element.textContent || element.innerText || '';
    if (!text.trim()) {
      throw new Error('Nothing to copy');
    }

    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(() => {
        showCopyFeedback(true);
      }).catch(err => {
        console.warn('Clipboard API failed, using fallback:', err);
        fallbackCopy(text);
      });
    } else {
      fallbackCopy(text);
    }
    
  } catch (error) {
    console.error('Copy error:', error);
    showCopyFeedback(false, error.message);
  }
}

function fallbackCopy(text) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.left = '-999999px';
  textArea.style.top = '-999999px';
  
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  
  try {
    const successful = document.execCommand('copy');
    showCopyFeedback(successful);
  } catch (err) {
    console.error('Fallback copy failed:', err);
    showCopyFeedback(false, 'Copy failed');
  } finally {
    document.body.removeChild(textArea);
  }
}

function showCopyFeedback(success, message = null) {
  const text = success 
    ? (window.i18next ? window.i18next.t('copied') : 'Copied!')
    : (message || (window.i18next ? window.i18next.t('errors.copy_error') : 'Copy failed'));
    
  if (window.showNotification) {
    window.showNotification(text, success ? 'success' : 'error');
  } else {
    alert(text);
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
    
    button.addEventListener('click', () => {
      try {
        armInactivityTimerSafely();
        
        button.disabled = true;
        target.classList.remove('blurred');
        
        setTimeout(() => {
          target.classList.add('blurred');
          button.disabled = false;
        }, timeout);
      } catch (error) {
        console.error(`Reveal button error for ${buttonId}:`, error);
        button.disabled = false;
      }
    });
    
    console.log(`Reveal button setup completed: ${buttonId} -> ${targetId}`);
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
    if (timerContext.hasContext('generation')) {
      if (keyManager && typeof keyManager.updateLastActionTime === 'function') {
        keyManager.updateLastActionTime();
      }
    }
    
    eventBus.emit(EVENTS.TIMER_ARM_REQUEST);
  } catch (error) {
    console.warn('Timer arm failed:', error);
  }
}

export function setTimerContext(context, callback = null) {
  timerContext.setContext(context, callback);
}

export function clearTimerContext() {
  timerContext.clearContext();
}

// === GLOBAL INSTANCES ===
export const keyManager = new SecureKeyManager();
export const rateLimiter = new RateLimiter();

// === EVENT LISTENERS ===
eventBus.on(EVENTS.TIMER_ARM_REQUEST, () => {
  if (keyManager) {
    keyManager.updateLastActionTime();
  }
});

// === GLOBAL COMPATIBILITY ===
if (typeof window !== 'undefined') {
  window.copyToClipboard = copyToClipboard;
  window.armInactivityTimerSafely = armInactivityTimerSafely;
}

// === INITIALIZATION ===
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    setupRevealButton(ELEMENT_IDS.REVEAL_HD_KEY, ELEMENT_IDS.HD_MASTER_KEY);
    setupRevealButton(ELEMENT_IDS.REVEAL_MNEMONIC, ELEMENT_IDS.MNEMONIC_PHRASE);
    
    console.log('Security layer initialized');
  });
} else {
  setupRevealButton(ELEMENT_IDS.REVEAL_HD_KEY, ELEMENT_IDS.HD_MASTER_KEY);
  setupRevealButton(ELEMENT_IDS.REVEAL_MNEMONIC, ELEMENT_IDS.MNEMONIC_PHRASE);
  
  console.log('Security layer initialized');
}

console.log('Security module loaded');
