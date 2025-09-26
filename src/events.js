// Event System for NITO Wallet - VERSION 2.0.0

// === EVENT TYPES CONSTANTS ===
export const EVENTS = {
  // Wallet events
  WALLET_INITIALIZED: 'wallet:initialized',
  WALLET_IMPORTED: 'wallet:imported',
  WALLET_BALANCE_UPDATED: 'wallet:balance:updated',
  WALLET_ADDRESS_CHANGED: 'wallet:address:changed',
  WALLET_INFO_REQUEST: 'wallet:info:request',
  WALLET_INFO_RESPONSE: 'wallet:info:response',
  
  // Transaction events
  TRANSACTION_PREPARED: 'transaction:prepared',
  TRANSACTION_SIGNED: 'transaction:signed',
  TRANSACTION_BROADCAST: 'transaction:broadcast',
  TRANSACTION_CONFIRMED: 'transaction:confirmed',
  TRANSACTION_FAILED: 'transaction:failed',
  
  // Messaging events
  MESSAGE_SENT: 'messaging:sent',
  MESSAGE_RECEIVED: 'messaging:received',
  MESSAGE_ENCRYPTED: 'messaging:encrypted',
  MESSAGE_DECRYPTED: 'messaging:decrypted',
  PUBKEY_PUBLISHED: 'messaging:pubkey:published',
  
  // Security events
  SESSION_EXPIRED: 'security:session:expired',
  KEYS_CLEARED: 'security:keys:cleared',
  INACTIVITY_WARNING: 'security:inactivity:warning',
  TIMER_ARM_REQUEST: 'security:timer:arm',
  
  // UI events
  UI_LOADING_START: 'ui:loading:start',
  UI_LOADING_END: 'ui:loading:end',
  UI_ERROR_DISPLAY: 'ui:error:display',
  UI_SUCCESS_DISPLAY: 'ui:success:display',
  UI_THEME_CHANGED: 'ui:theme:changed',
  UI_LANGUAGE_CHANGED: 'ui:language:changed',
  
  // Blockchain events
  BLOCK_NEW: 'blockchain:block:new',
  UTXO_UPDATED: 'blockchain:utxo:updated',
  FEE_RATE_UPDATED: 'blockchain:fee:updated',
  
  // System events
  SYSTEM_ERROR: 'system:error',
  SYSTEM_READY: 'system:ready',
  SYSTEM_SHUTDOWN: 'system:shutdown'
};

// === EVENT DATA VALIDATION SCHEMAS ===
const EVENT_SCHEMAS = {
  [EVENTS.WALLET_IMPORTED]: ['addresses', 'importType'],
  [EVENTS.TRANSACTION_PREPARED]: ['hex', 'txid', 'fees'],
  [EVENTS.MESSAGE_SENT]: ['messageId', 'recipient', 'chunks'],
  [EVENTS.UI_ERROR_DISPLAY]: ['message', 'type'],
  [EVENTS.WALLET_INFO_RESPONSE]: ['address', 'isReady']
};

// === ENHANCED EVENT MEDIATOR WITH COMPREHENSIVE PROTECTION ===
export class EventMediator {
  constructor(options = {}) {
    this.listeners = new Map();
    this.debugMode = options.debug || false;
    this.maxListeners = options.maxListeners || 30; // Réduit encore plus
    this.eventHistory = options.keepHistory ? [] : null;
    
    // Anti-duplication tracking
    this.listenerFingerprints = new Map();
    this.functionBodies = new WeakMap();
    
    // Timers and cleanup
    this.cleanupTimer = setInterval(() => this.cleanup(), 180000); // 3 minutes
    this.performanceTimer = setInterval(() => this.performanceCleanup(), 300000); // 5 minutes
    
    // Enhanced anti-loop protection
    this.pendingRequests = new Set();
    this.requestCounts = new Map();
    this.maxRequestsPerSecond = 2; // Encore plus strict
    this.requestCooldowns = new Map();
    this.globalRequestBlacklist = new Set();
    
    // Protection contre les events en cascade
    this.eventCallStack = [];
    this.maxCallStackDepth = 2; // Plus strict
    this.recursionProtection = new Map();
    
    // Performance monitoring
    this.listenerExecutionTimes = new Map();
    this.slowListeners = new Set();
    
    if (this.debugMode) {
      console.log('[EVENTS] EventMediator v2.0.0 initialized with enhanced protection');
    }
  }

  // === FUNCTION FINGERPRINTING FOR DUPLICATE DETECTION ===
  getFunctionFingerprint(func) {
    if (this.functionBodies.has(func)) {
      return this.functionBodies.get(func);
    }
    
    const funcStr = func.toString();
    const fingerprint = this.hashString(funcStr);
    this.functionBodies.set(func, fingerprint);
    return fingerprint;
  }

  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(36);
  }

  // === CORE EVENT METHODS WITH ENHANCED PROTECTION ===
  on(event, callback, options = {}) {
    if (!this._validateEvent(event, callback)) return false;
    
    const { priority = 0, once = false, context = null } = options;
    
    // Generate fingerprint to detect duplicates
    const fingerprint = this.getFunctionFingerprint(callback);
    const fingerprintKey = `${event}:${fingerprint}`;
    
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    
    const listeners = this.listeners.get(event);
    
    // STRICT protection against duplicate listeners
    const existingByCallback = listeners.findIndex(l => l.callback === callback);
    const existingByFingerprint = listeners.findIndex(l => l.fingerprint === fingerprint);
    
    if (existingByCallback !== -1) {
      console.warn(`[EVENTS] Exact duplicate listener blocked for event: ${event}`);
      return listeners[existingByCallback].id;
    }
    
    if (existingByFingerprint !== -1) {
      console.warn(`[EVENTS] Functionally identical listener blocked for event: ${event}`);
      return listeners[existingByFingerprint].id;
    }
    
    // Check if fingerprint exists globally
    if (this.listenerFingerprints.has(fingerprintKey)) {
      console.warn(`[EVENTS] Global duplicate listener blocked: ${event}`);
      return this.listenerFingerprints.get(fingerprintKey);
    }
    
    // Protection against listener overflow
    if (listeners.length >= this.maxListeners) {
      console.warn(`[EVENTS] Max listeners (${this.maxListeners}) exceeded for event: ${event}`);
      this._emergencyCleanupListeners(event);
      
      if (listeners.length >= this.maxListeners) {
        console.error(`[EVENTS] Still too many listeners after cleanup - blocking new listener`);
        return false;
      }
    }
    
    const listenerData = {
      callback,
      priority,
      id: this._generateId(),
      created: Date.now(),
      once,
      context,
      fingerprint,
      executionCount: 0,
      lastExecuted: 0,
      avgExecutionTime: 0
    };
    
    // Insert by priority
    const insertIndex = listeners.findIndex(l => l.priority < priority);
    if (insertIndex === -1) {
      listeners.push(listenerData);
    } else {
      listeners.splice(insertIndex, 0, listenerData);
    }
    
    // Track globally
    this.listenerFingerprints.set(fingerprintKey, listenerData.id);
    
    if (this.debugMode) {
      console.log(`[EVENTS] Listener added: ${event} (priority: ${priority}, total: ${listeners.length}, id: ${listenerData.id})`);
    }
    
    return listenerData.id;
  }

  once(event, callback, options = {}) {
    if (!this._validateEvent(event, callback)) return false;
    
    const { timeout = 2000 } = options; // Réduit de 3000 à 2000ms
    const listenerId = this._generateId();
    
    const wrappedCallback = (...args) => {
      try {
        callback(...args);
      } catch (error) {
        this._handleError('once_callback', error, { event, listenerId });
      } finally {
        this.off(event, listenerId);
      }
    };
    
    const id = this.on(event, wrappedCallback, { ...options, once: true });
    
    if (timeout > 0) {
      setTimeout(() => {
        if (this.listeners.has(event)) {
          this.off(event, id);
          if (this.debugMode) {
            console.log(`[EVENTS] Once listener timed out: ${event}`);
          }
        }
      }, timeout);
    }
    
    return id;
  }

  emit(event, data = null, options = {}) {
    const { async = false, validateData = false } = options;
    
    // ENHANCED protection against infinite loops
    if (this.eventCallStack.length > this.maxCallStackDepth) {
      console.warn(`[EVENTS] Max call stack depth (${this.maxCallStackDepth}) exceeded for event: ${event}`);
      return false;
    }
    
    // Check for recursive calls
    const recursionKey = `${event}:${Date.now()}`;
    if (this.recursionProtection.has(event)) {
      const lastCall = this.recursionProtection.get(event);
      if (Date.now() - lastCall < 100) { // 100ms recursion window
        console.warn(`[EVENTS] Recursion protection triggered for: ${event}`);
        return false;
      }
    }
    
    this.recursionProtection.set(event, Date.now());
    this.eventCallStack.push(event);
    
    try {
      // Enhanced protection for WALLET_INFO_REQUEST
      if (event === EVENTS.WALLET_INFO_REQUEST) {
        const now = Date.now();
        
        // Check blacklist
        if (this.globalRequestBlacklist.has(event)) {
          console.log(`[EVENTS] Event blacklisted: ${event}`);
          return false;
        }
        
        // Check cooldown
        if (this.requestCooldowns.has(event)) {
          const lastRequest = this.requestCooldowns.get(event);
          if (now - lastRequest < 500) { // Increased cooldown to 500ms
            if (this.debugMode) {
              console.log(`[EVENTS] Request in cooldown: ${event}`);
            }
            return false;
          }
        }
        
        this.requestCooldowns.set(event, now);
        
        // Rate limiting
        const requests = this.requestCounts.get(event) || [];
        const recentRequests = requests.filter(time => now - time < 1000);
        
        if (recentRequests.length >= this.maxRequestsPerSecond) {
          console.warn(`[EVENTS] Rate limit exceeded for event: ${event} - temporarily blacklisting`);
          this.globalRequestBlacklist.add(event);
          setTimeout(() => {
            this.globalRequestBlacklist.delete(event);
            console.log(`[EVENTS] Event removed from blacklist: ${event}`);
          }, 5000);
          return false;
        }
        
        recentRequests.push(now);
        this.requestCounts.set(event, recentRequests);
      }
      
      if (validateData && !this._validateEventData(event, data)) {
        console.warn(`[EVENTS] Invalid data for event: ${event}`);
        return false;
      }
      
      if (this.eventHistory) {
        this.eventHistory.push({
          event,
          data,
          timestamp: Date.now(),
          async
        });
        
        if (this.eventHistory.length > 30) { // Réduit de 50 à 30
          this.eventHistory.shift();
        }
      }
      
      const listeners = this.listeners.get(event) || [];
      
      if (this.debugMode && event === EVENTS.WALLET_INFO_REQUEST) {
        console.log(`[EVENTS] Emitting: ${event} to ${listeners.length} listeners`);
      }
      
      if (!listeners.length) {
        return true;
      }
      
      const eventContext = {
        event,
        data,
        timestamp: Date.now()
      };
      
      if (async) {
        setTimeout(() => {
          this._executeListeners(listeners, eventContext);
        }, 0);
      } else {
        this._executeListeners(listeners, eventContext);
      }
      
      return true;
      
    } finally {
      this.eventCallStack.pop();
      
      // Clean recursion protection after a delay
      setTimeout(() => {
        this.recursionProtection.delete(event);
      }, 200);
    }
  }

  off(event, callbackOrId) {
    const listeners = this.listeners.get(event);
    if (!listeners) return false;
    
    let removed = false;
    
    for (let i = listeners.length - 1; i >= 0; i--) {
      const listener = listeners[i];
      
      if (typeof callbackOrId === 'string' && listener.id === callbackOrId) {
        // Remove from global tracking
        const fingerprintKey = `${event}:${listener.fingerprint}`;
        this.listenerFingerprints.delete(fingerprintKey);
        
        listeners.splice(i, 1);
        removed = true;
        break;
      } else if (typeof callbackOrId === 'function' && listener.callback === callbackOrId) {
        // Remove from global tracking
        const fingerprintKey = `${event}:${listener.fingerprint}`;
        this.listenerFingerprints.delete(fingerprintKey);
        
        listeners.splice(i, 1);
        removed = true;
      }
    }
    
    if (listeners.length === 0) {
      this.listeners.delete(event);
    }
    
    if (this.debugMode && removed) {
      console.log(`[EVENTS] Listener removed: ${event}`);
    }
    
    return removed;
  }

  removeAllListeners(event) {
    if (this.listeners.has(event)) {
      const listeners = this.listeners.get(event);
      
      // Remove from global tracking
      listeners.forEach(listener => {
        const fingerprintKey = `${event}:${listener.fingerprint}`;
        this.listenerFingerprints.delete(fingerprintKey);
      });
      
      const count = listeners.length;
      this.listeners.delete(event);
      
      if (this.debugMode) {
        console.log(`[EVENTS] All ${count} listeners removed for event: ${event}`);
      }
    }
  }

  // === EMERGENCY CLEANUP ===
  _emergencyCleanupListeners(event) {
    const listeners = this.listeners.get(event) || [];
    const now = Date.now();
    
    // Remove very old listeners (> 1 minute)
    const activeListeners = listeners.filter(listener => {
      const age = now - listener.created;
      return age <= 60000;
    });
    
    // If still too many, keep only the most recently used
    if (activeListeners.length >= this.maxListeners) {
      activeListeners.sort((a, b) => b.lastExecuted - a.lastExecuted);
      activeListeners.splice(Math.floor(this.maxListeners * 0.6)); // Keep 60% of limit
    }
    
    // Update global tracking
    listeners.forEach(listener => {
      const fingerprintKey = `${event}:${listener.fingerprint}`;
      this.listenerFingerprints.delete(fingerprintKey);
    });
    
    activeListeners.forEach(listener => {
      const fingerprintKey = `${event}:${listener.fingerprint}`;
      this.listenerFingerprints.set(fingerprintKey, listener.id);
    });
    
    this.listeners.set(event, activeListeners);
    console.log(`[EVENTS] Emergency cleanup for ${event}: ${listeners.length} -> ${activeListeners.length}`);
  }

  // === PERFORMANCE MONITORING ===
  _executeListeners(listeners, eventContext) {
    // Copy to prevent modifications during execution
    const listenersToExecute = [...listeners];
    
    listenersToExecute.forEach((listener, index) => {
      const startTime = performance.now();
      
      try {
        listener.callback(eventContext.data, eventContext);
        
        // Update performance stats
        const executionTime = performance.now() - startTime;
        listener.executionCount++;
        listener.lastExecuted = Date.now();
        listener.avgExecutionTime = (listener.avgExecutionTime + executionTime) / 2;
        
        // Track slow listeners
        if (executionTime > 100) { // 100ms threshold
          this.slowListeners.add(listener.id);
          console.warn(`[EVENTS] Slow listener detected: ${eventContext.event} (${executionTime.toFixed(2)}ms)`);
        }
        
        // Remove "once" listeners
        if (listener.once) {
          const originalListeners = this.listeners.get(eventContext.event);
          if (originalListeners) {
            const listenerIndex = originalListeners.findIndex(l => l.id === listener.id);
            if (listenerIndex !== -1) {
              // Remove from global tracking
              const fingerprintKey = `${eventContext.event}:${listener.fingerprint}`;
              this.listenerFingerprints.delete(fingerprintKey);
              
              originalListeners.splice(listenerIndex, 1);
            }
          }
        }
      } catch (error) {
        this._handleError('listener_execution', error, {
          event: eventContext.event,
          listenerId: listener.id,
          listenerIndex: index
        });
      }
    });
  }

  // === ENHANCED CLEANUP METHODS ===
  cleanup() {
    const now = Date.now();
    const maxAge = 900000; // Réduit de 1800000 (30min) à 900000 (15min)
    
    for (const [event, listeners] of this.listeners.entries()) {
      const filteredListeners = listeners.filter(listener => {
        const age = now - listener.created;
        const isActive = age <= maxAge && listener.executionCount > 0;
        const isRecent = age <= 30000; // Keep very recent listeners
        
        return isActive || isRecent;
      });
      
      // Update global tracking for removed listeners
      const removedListeners = listeners.filter(l => !filteredListeners.includes(l));
      removedListeners.forEach(listener => {
        const fingerprintKey = `${event}:${listener.fingerprint}`;
        this.listenerFingerprints.delete(fingerprintKey);
      });
      
      if (filteredListeners.length === 0) {
        this.listeners.delete(event);
      } else if (filteredListeners.length < listeners.length) {
        this.listeners.set(event, filteredListeners);
      }
    }
    
    // Clean history
    if (this.eventHistory) {
      this.eventHistory = this.eventHistory.filter(entry => {
        return (now - entry.timestamp) < maxAge;
      });
    }
    
    // Clean request tracking
    for (const [event, requests] of this.requestCounts.entries()) {
      const recentRequests = requests.filter(time => now - time < 5000);
      if (recentRequests.length === 0) {
        this.requestCounts.delete(event);
      } else {
        this.requestCounts.set(event, recentRequests);
      }
    }
    
    // Clean cooldowns
    for (const [event, lastRequest] of this.requestCooldowns.entries()) {
      if (now - lastRequest > 10000) {
        this.requestCooldowns.delete(event);
      }
    }
    
    if (this.debugMode) {
      console.log(`[EVENTS] Cleanup completed - Events: ${this.listeners.size}, Fingerprints: ${this.listenerFingerprints.size}`);
    }
  }

  performanceCleanup() {
    // Remove slow listeners that haven't improved
    for (const listenerId of this.slowListeners) {
      let found = false;
      for (const [event, listeners] of this.listeners.entries()) {
        const listenerIndex = listeners.findIndex(l => l.id === listenerId);
        if (listenerIndex !== -1) {
          const listener = listeners[listenerIndex];
          if (listener.avgExecutionTime > 50) { // Still slow
            console.warn(`[EVENTS] Removing persistently slow listener: ${event}`);
            this.off(event, listenerId);
          }
          found = true;
          break;
        }
      }
      if (!found) {
        this.slowListeners.delete(listenerId);
      }
    }
    
    console.log(`[EVENTS] Performance cleanup completed`);
  }

  // === UTILITY METHODS ===
  listenerCount(event) {
    const listeners = this.listeners.get(event);
    return listeners ? listeners.length : 0;
  }

  getEvents() {
    return Array.from(this.listeners.keys());
  }

  getHistory() {
    return this.eventHistory ? [...this.eventHistory] : [];
  }

  getStats() {
    return {
      totalEvents: this.listeners.size,
      totalListeners: Array.from(this.listeners.values()).reduce((sum, arr) => sum + arr.length, 0),
      totalFingerprints: this.listenerFingerprints.size,
      slowListeners: this.slowListeners.size,
      activeRequests: this.pendingRequests.size,
      blacklistedEvents: this.globalRequestBlacklist.size
    };
  }

  destroy() {
    // Clear all timers
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    
    if (this.performanceTimer) {
      clearInterval(this.performanceTimer);
      this.performanceTimer = null;
    }
    
    // Clear all data structures
    this.listeners.clear();
    this.listenerFingerprints.clear();
    this.requestCounts.clear();
    this.requestCooldowns.clear();
    this.globalRequestBlacklist.clear();
    this.eventCallStack = [];
    this.recursionProtection.clear();
    this.slowListeners.clear();
    
    if (this.eventHistory) {
      this.eventHistory.length = 0;
    }
    
    if (this.debugMode) {
      console.log('[EVENTS] EventMediator destroyed');
    }
  }

  // === PRIVATE METHODS ===
  _validateEvent(event, callback) {
    if (typeof event !== 'string' || !event.trim()) {
      console.error('[EVENTS] Event name must be a non-empty string');
      return false;
    }
    
    if (typeof callback !== 'function') {
      console.error('[EVENTS] Event callback must be a function');
      return false;
    }
    
    return true;
  }

  _validateEventData(event, data) {
    const schema = EVENT_SCHEMAS[event];
    if (!schema) return true;
    
    if (!data || typeof data !== 'object') return false;
    
    return schema.every(field => data.hasOwnProperty(field));
  }

  _handleError(type, error, context = {}) {
    console.error(`[EVENTS] ${type} error:`, error, context);
    
    if (context.event !== 'system:error') {
      setTimeout(() => {
        this.emit('system:error', { type, error: error.message, context }, { async: true });
      }, 0);
    }
  }

  _generateId() {
    return `listener_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// === GLOBAL EVENT BUS INSTANCE ===
export const eventBus = new EventMediator({
  debug: false,
  maxListeners: 30, // Réduit encore plus
  keepHistory: false
});

// === UTILITY FUNCTIONS ===
export const createEventPromise = (event, timeout = 2000) => {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      eventBus.off(event, handler);
      reject(new Error(`Event ${event} timeout after ${timeout}ms`));
    }, timeout);

    const handler = (data) => {
      clearTimeout(timeoutId);
      resolve(data);
    };

    eventBus.once(event, handler, { timeout });
  });
};

export const waitForEvent = (event, condition = null, timeout = 2000) => {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      eventBus.off(event, handler);
      reject(new Error(`Event ${event} condition timeout`));
    }, timeout);

    const handler = (data, context) => {
      if (!condition || condition(data, context)) {
        clearTimeout(timeoutId);
        eventBus.off(event, handler);
        resolve(data);
      }
    };

    eventBus.on(event, handler);
  });
};

// === CROSS-MODULE COMMUNICATION HELPERS - ENHANCED ===
let walletInfoRequestInProgress = false;
let lastWalletInfoResponse = { address: '', isReady: false };
let walletInfoCooldown = 0;
let walletInfoRequestCount = 0;
const MAX_WALLET_INFO_REQUESTS_PER_MINUTE = 10;

export const requestWalletInfo = () => {
  const now = Date.now();
  
  // Enhanced cooldown de 1 seconde
  if (now - walletInfoCooldown < 1000) {
    return Promise.resolve(lastWalletInfoResponse);
  }
  
  // Rate limiting par minute
  walletInfoRequestCount++;
  if (walletInfoRequestCount > MAX_WALLET_INFO_REQUESTS_PER_MINUTE) {
    console.warn('[EVENTS] Wallet info request rate limit exceeded');
    return Promise.resolve(lastWalletInfoResponse);
  }
  
  // Reset counter every minute
  setTimeout(() => {
    walletInfoRequestCount = Math.max(0, walletInfoRequestCount - 1);
  }, 60000);
  
  // Éviter les requêtes multiples simultanées
  if (walletInfoRequestInProgress) {
    return Promise.resolve(lastWalletInfoResponse);
  }
  
  walletInfoRequestInProgress = true;
  walletInfoCooldown = now;
  
  return createEventPromise(EVENTS.WALLET_INFO_RESPONSE, 800) // Réduit à 800ms
    .then((result) => {
      lastWalletInfoResponse = result || { address: '', isReady: false };
      return lastWalletInfoResponse;
    })
    .catch(() => {
      return lastWalletInfoResponse;
    })
    .finally(() => {
      walletInfoRequestInProgress = false;
      // Émettre la requête seulement si pas déjà en cours
      setTimeout(() => {
        if (!walletInfoRequestInProgress) {
          eventBus.emit(EVENTS.WALLET_INFO_REQUEST);
        }
      }, 50); // Réduit de 10ms à 50ms
    });
};

export const armSecurityTimer = () => {
  eventBus.emit(EVENTS.TIMER_ARM_REQUEST);
};

// === ENHANCED PAGE UNLOAD CLEANUP ===
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', () => {
    console.log('[EVENTS] Page unloading - destroying event system');
    eventBus.destroy();
  });
  
  // Also handle page hide for mobile
  window.addEventListener('pagehide', () => {
    console.log('[EVENTS] Page hiding - cleaning up event system');
    eventBus.cleanup();
  });
}

// === GLOBAL ACCESS ===
if (typeof window !== 'undefined') {
  window.eventBus = eventBus;
  window.EVENTS = EVENTS;
  
  // Debug helper
  window.getEventStats = () => eventBus.getStats();
}

console.log('Events system v2.0.0 loaded');
