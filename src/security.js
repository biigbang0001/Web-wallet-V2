// Security Layer for NITO Wallet
// Handles encryption, key management, validation

import { SECURITY_CONFIG, VALIDATION_PATTERNS, ELEMENT_IDS, ERROR_CODES, FEATURE_FLAGS } from './config.js';
import { eventBus, EVENTS } from './events.js';

// === TRANSLATION HELPER ===
function getTranslation(key, fallback, params = {}) {
  const t = (window.i18next && typeof window.i18next.t === 'function') 
    ? window.i18next.t 
    : () => fallback || key;
  return t(key, { ...params, defaultValue: fallback });
}

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
    this.isInactivityActive = false; // Nouveau: track l'état du timer d'inactivité
    
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
      const errorMsg = getTranslation('security.failed_to_encrypt', 'Échec du chiffrement des données sensibles');
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
        console.warn('Maximum key storage exceeded, clearing oldest keys');
        this.clearOldestKeys(1);
      }
      
      const encrypted = await this.encrypt(keyData);
      this.encryptedData.set(id, {
        ...encrypted,
        timestamp: Date.now()
      });
      
      console.log(`[SECURITY] Secure key stored: ${id}`);
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
      console.log(`[SECURITY] Cleared old key: ${id}`);
    });
  }

  // Amélioration: Méthode pour vérifier si une opération est en cours
  isOperationInProgress() {
    if (typeof window !== 'undefined' && window.isOperationActive) {
      return window.isOperationActive();
    }
    return false;
  }

  // Amélioration: Méthode pour vérifier si on est dans une phase d'import/génération
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

  // CORRECTION PRINCIPALE: Distinction entre types de nettoyage
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
      
      // CORRECTION: Ne pas arrêter le timer d'inactivité sauf pour les vrais timeouts
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
      
      // CORRECTION: Auto-reload seulement pour les vrais timeouts de sécurité
      const securityTimeouts = ['inactivity_timeout', 'session_timeout'];
      if (FEATURE_FLAGS.AUTO_RELOAD_ON_KEY_CLEAR && securityTimeouts.includes(reason)) {
        console.log(`[SECURITY] Security timeout detected (${reason}), scheduling auto-reload`);
        this.scheduleAutoReload();
      } else {
        console.log(`[SECURITY] Keys cleared for reason: ${reason}, no auto-reload needed`);
      }
      
    } catch (error) {
      console.error('Error clearing keys:', error);
    }
  }

  scheduleAutoReload() {
    console.log('[SECURITY] Scheduling auto-reload check...');
    
    const checkAndReload = () => {
      // Vérification plus stricte des opérations
      if (this.isWalletOperationInProgress()) {
        console.log('[SECURITY] Wallet operation in progress, delaying auto-reload...');
        setTimeout(checkAndReload, 5000);
        return;
      }
      
      if (this.isOperationInProgress()) {
        console.log('[SECURITY] General operation in progress, delaying auto-reload...');
        setTimeout(checkAndReload, 3000);
        return;
      }
      
      this.executeAutoReload();
    };
    
    // Attendre plus longtemps avant le premier check
    setTimeout(checkAndReload, 5000);
  }

  executeAutoReload() {
    console.log('[SECURITY] Executing auto-reload...');
    
    // Vérification finale
    if (this.isWalletOperationInProgress()) {
      console.log('[SECURITY] Aborting auto-reload, wallet operation detected');
      return;
    }
    
    // CORRECTION: Afficher une notification traduite avant le rechargement
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
    
    const title = getTranslation('security.session_expired_title', 'Session expirée');
    const message = getTranslation('security.auto_reload_message', 'Rechargement automatique...');
    
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
        <div style="font-size: 3rem; margin-bottom: 1rem;">🔐</div>
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
    // Surveiller périodiquement les opérations pour un rechargement sûr
    this.operationCheckTimer = setInterval(() => {
      // Fonction de monitoring passive
    }, 5000);
  }

  // CORRECTION PRINCIPALE: Amélioration de la gestion du timer d'inactivité
  updateAccess() {
    const now = Date.now();
    this.lastAccess = now;
    
    // CORRECTION: Réinitialiser complètement le timer d'inactivité
    this.resetInactivityTimer();
    
    console.log(`[SECURITY] Access updated, timer reset to 10 minutes`);
  }

  setupAutoCleanup() {
    if (this.cleanupTimer) clearTimeout(this.cleanupTimer);
    this.cleanupTimer = setTimeout(() => {
      // CORRECTION: Spécifier la raison correcte
      this.clearAll('session_timeout');
    }, SECURITY_CONFIG.SESSION_TIMEOUT);
  }

  setupPageHideCleanup() {
    const cleanup = () => {
      // CORRECTION: Spécifier la raison et ne nettoyer que l'affichage
      this.clearSensitiveDisplayOnly('page_unload');
      this.clearSensitiveFields();
    };
    
    window.addEventListener('pagehide', cleanup);
    window.addEventListener('beforeunload', cleanup);
  }

  // CORRECTION PRINCIPALE: Gestion complète du timer d'inactivité
  setupInactivityTimer() {
    this.isInactivityActive = true;
    this.resetInactivityTimer();
    this.startTimerDisplay();
  }

  resetInactivityTimer() {
    // CORRECTION: Nettoyer l'ancien timer et en créer un nouveau
    if (this.inactivityTimer) {
      clearTimeout(this.inactivityTimer);
      this.inactivityTimer = null;
    }
    
    // CORRECTION: Créer un nouveau timer de 10 minutes exactement
    this.inactivityTimer = setTimeout(() => {
      console.log('[SECURITY] Inactivity timeout reached - clearing sensitive data');
      this.clearSensitiveData('inactivity_timeout');
      eventBus.emit(EVENTS.SESSION_EXPIRED, { reason: 'inactivity' });
    }, SECURITY_CONFIG.INACTIVITY_TIMEOUT);
    
    this.isInactivityActive = true;
    console.log(`[SECURITY] Inactivity timer reset - ${SECURITY_CONFIG.INACTIVITY_TIMEOUT / 60000} minutes`);
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
    
    // CORRECTION: Quand le timer atteint 0, déclencher le timeout
    if (remaining <= 0 && this.isInactivityActive) {
      clearInterval(this.displayTimer);
      this.displayTimer = null;
    }
  }

  // CORRECTION: Distinction entre nettoyage d'affichage et nettoyage complet
  clearSensitiveData(reason = 'inactivity') {
    console.log(`[SECURITY] Clearing sensitive display data (reason: ${reason}), wallet keys preserved`);
    
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

    // CORRECTION: Émettre l'événement avec la raison
    eventBus.emit(EVENTS.INACTIVITY_WARNING, { reason });
    
    // CORRECTION: Pour les vrais timeouts d'inactivité, déclencher l'auto-reload
    if (reason === 'inactivity_timeout' && FEATURE_FLAGS.AUTO_RELOAD_ON_KEY_CLEAR) {
      this.scheduleAutoReload();
    }
  }

  // NOUVELLE MÉTHODE: Nettoyage d'affichage seulement (pour page unload)
  clearSensitiveDisplayOnly(reason = 'page_unload') {
    console.log(`[SECURITY] Clearing sensitive display only (reason: ${reason})`);
    
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

  // CORRECTION: S'assurer que chaque action utilisateur réinitialise le timer
  updateLastActionTime() {
    console.log('[SECURITY] User action detected - resetting inactivity timer');
    this.updateAccess();
  }
}

// === CREDENTIAL DERIVATION ===
export async function deriveFromCredentials(email, password, wordCount = 24) {
  try {
    const normalizedEmail = email.trim().toLowerCase();
    
    if (!validateInput(normalizedEmail, 'email')) {
      const errorMsg = getTranslation('errors.enter_email_password', 'Format d\'email invalide');
      throw new Error(errorMsg);
    }
    
    if (!password || password.length < 1) {
      const errorMsg = getTranslation('errors.enter_email_password', 'Le mot de passe ne peut pas être vide');
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

// === ENHANCED INPUT VALIDATION ===
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

// === ENHANCED RATE LIMITER ===
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
        `Limite de taux dépassée. Veuillez attendre ${waitTime} secondes avant de réessayer.`,
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

// === ENHANCED CLIPBOARD OPERATIONS ===
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
      const errorMsg = getTranslation('security.element_not_found', 'Élément non trouvé');
      throw new Error(errorMsg);
    }

    if (element.classList.contains('blurred')) {
      const errorMsg = getTranslation('security.please_reveal_first', 'Veuillez d\'abord révéler le contenu');
      throw new Error(errorMsg);
    }

    const text = element.textContent || element.innerText || '';
    if (!text.trim()) {
      const errorMsg = getTranslation('security.nothing_to_copy', 'Rien à copier');
      throw new Error(errorMsg);
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
    const errorMsg = getTranslation('security.copy_failed', 'Échec de la copie');
    showCopyFeedback(false, errorMsg);
  } finally {
    document.body.removeChild(textArea);
  }
}

function showCopyFeedback(success, message = null) {
  const text = success 
    ? getTranslation('security.copied', 'Copié !')
    : (message || getTranslation('security.copy_failed', 'Échec de la copie'));
    
  if (window.showNotification) {
    window.showNotification(text, success ? 'success' : 'error');
  } else {
    alert(text);
  }
}

// === ENHANCED REVEAL BUTTON SETUP ===
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
    
    // Remove existing listeners to prevent duplicates
    const newButton = button.cloneNode(true);
    button.parentNode.replaceChild(newButton, button);
    
    newButton.addEventListener('click', () => {
      try {
        armInactivityTimerSafely();
        
        newButton.disabled = true;
        target.classList.remove('blurred');
        
        console.log(`[SECURITY] Content revealed: ${targetId}`);
        
        setTimeout(() => {
          target.classList.add('blurred');
          newButton.disabled = false;
          console.log(`[SECURITY] Content auto-hidden: ${targetId}`);
        }, timeout);
      } catch (error) {
        console.error(`Reveal button error for ${buttonId}:`, error);
        newButton.disabled = false;
      }
    });
    
    console.log(`[SECURITY] Reveal button setup completed: ${buttonId} -> ${targetId}`);
    return true;
  } catch (error) {
    console.error(`Failed to setup reveal button ${buttonId}:`, error);
    return false;
  }
}

// === TIMER MANAGEMENT ===
const timerContext = new TimerContext();

// CORRECTION PRINCIPALE: Amélioration de armInactivityTimerSafely
export function armInactivityTimerSafely() {
  try {
    console.log('[SECURITY] armInactivityTimerSafely called - resetting timer');
    
    if (timerContext.hasContext('generation')) {
      if (keyManager && typeof keyManager.updateLastActionTime === 'function') {
        keyManager.updateLastActionTime();
      }
    }
    
    // CORRECTION: Toujours réinitialiser le timer d'inactivité
    if (keyManager && typeof keyManager.updateLastActionTime === 'function') {
      keyManager.updateLastActionTime();
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

eventBus.on(EVENTS.KEYS_CLEARED, (data) => {
  console.log('[SECURITY] Keys cleared event received:', data?.reason || 'unknown reason');
});

eventBus.on(EVENTS.SESSION_EXPIRED, (data) => {
  console.log('[SECURITY] Session expired event received:', data);
  
  // CORRECTION: Afficher un avertissement traduit avant l'auto-reload
  const warningMsg = getTranslation('security.session_timeout_warning', 
    'Session expirée pour cause d\'inactivité. Le wallet va se recharger automatiquement.');
  
  // Afficher une notification non-bloquante
  if (window.showNotification) {
    window.showNotification(warningMsg, 'warning');
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
    
    console.log('[SECURITY] Security layer initialized - Version 2.0.0');
  });
} else {
  setupRevealButton(ELEMENT_IDS.REVEAL_HD_KEY, ELEMENT_IDS.HD_MASTER_KEY);
  setupRevealButton(ELEMENT_IDS.REVEAL_MNEMONIC, ELEMENT_IDS.MNEMONIC_PHRASE);
  
  console.log('[SECURITY] Security layer initialized - Version 2.0.0');
}
