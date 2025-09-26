// Event System for NITO Wallet - FIXED VERSION
// Resolves circular dependencies between modules and prevents event duplication

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
  
  // Blockchain events
  BLOCK_NEW: 'blockchain:block:new',
  UTXO_UPDATED: 'blockchain:utxo:updated',
  FEE_RATE_UPDATED: 'blockchain:fee:updated',
  
  // System events
  SYSTEM_ERROR: 'system:error',
  SYSTEM_READY: 'system:ready'
};

// === EVENT DATA VALIDATION SCHEMAS ===
const EVENT_SCHEMAS = {
  [EVENTS.WALLET_IMPORTED]: ['addresses', 'importType'],
  [EVENTS.TRANSACTION_PREPARED]: ['hex', 'txid', 'fees'],
  [EVENTS.MESSAGE_SENT]: ['messageId', 'recipient', 'chunks'],
  [EVENTS.UI_ERROR_DISPLAY]: ['message', 'type'],
  [EVENTS.WALLET_INFO_RESPONSE]: ['address', 'isReady']
};

// === FIXED EVENT MEDIATOR WITH PROPER DUPLICATION PREVENTION ===
export class EventMediator {
  constructor(options = {}) {
    this.listeners = new Map();
    this.debugMode = options.debug || false;
    this.maxListeners = options.maxListeners || 50; // Réduit pour éviter l'accumulation
    this.eventHistory = options.keepHistory ? [] : null;
    
    this.cleanupTimer = setInterval(() => this.cleanup(), 300000);
    
    // Anti-loop protection RENFORCÉE
    this.pendingRequests = new Set();
    this.requestCounts = new Map();
    this.maxRequestsPerSecond = 3; // Réduit de 5 à 3
    this.requestCooldowns = new Map(); // Nouveaux cooldowns
    
    // Protection contre les events en cascade
    this.eventCallStack = [];
    this.maxCallStackDepth = 3;
    
    if (this.debugMode) {
      console.log('EventMediator initialized with enhanced anti-duplication');
    }
  }

  // === CORE EVENT METHODS WITH DUPLICATION FIXES ===
  on(event, callback, options = {}) {
    if (!this._validateEvent(event, callback)) return false;
    
    const { priority = 0, once = false } = options;
    
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    
    const listeners = this.listeners.get(event);
    
    // PROTECTION STRICTE contre les listeners dupliqués
    const existingIndex = listeners.findIndex(l => l.callback === callback);
    if (existingIndex !== -1) {
      console.warn(`Duplicate listener blocked for event: ${event}`);
      return listeners[existingIndex].id;
    }
    
    // Protection contre le dépassement de listeners
    if (listeners.length >= this.maxListeners) {
      console.warn(`Max listeners exceeded for event: ${event} - cleaning up old listeners`);
      this._cleanupOldListeners(event);
      
      if (listeners.length >= this.maxListeners) {
        console.error(`Still too many listeners for event: ${event} - blocking new listener`);
        return false;
      }
    }
    
    const listenerData = {
      callback,
      priority,
      id: this._generateId(),
      created: Date.now(),
      once
    };
    
    const insertIndex = listeners.findIndex(l => l.priority < priority);
    if (insertIndex === -1) {
      listeners.push(listenerData);
    } else {
      listeners.splice(insertIndex, 0, listenerData);
    }
    
    if (this.debugMode) {
      console.log(`Event listener added: ${event} (priority: ${priority}, total: ${listeners.length})`);
    }
    
    return listenerData.id;
  }

  once(event, callback, options = {}) {
    if (!this._validateEvent(event, callback)) return false;
    
    const { timeout = 3000 } = options; // Réduit de 5000 à 3000ms
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
            console.log(`Once listener timed out for event: ${event}`);
          }
        }
      }, timeout);
    }
    
    return id;
  }

  emit(event, data = null, options = {}) {
    const { async = false, validateData = false } = options;
    
    // PROTECTION RENFORCÉE contre les boucles infinies
    if (this.eventCallStack.length > this.maxCallStackDepth) {
      console.warn(`Max call stack depth exceeded for event: ${event}`);
      return false;
    }
    
    this.eventCallStack.push(event);
    
    try {
      // Anti-loop protection spécifique pour WALLET_INFO_REQUEST
      if (event === EVENTS.WALLET_INFO_REQUEST) {
        const now = Date.now();
        const cooldownKey = `${event}:${now}`;
        
        // Vérifier si on est dans un cooldown
        if (this.requestCooldowns.has(event)) {
          const lastRequest = this.requestCooldowns.get(event);
          if (now - lastRequest < 1000) { // 1 seconde de cooldown
            if (this.debugMode) {
              console.log(`Request in cooldown: ${event}`);
            }
            return false;
          }
        }
        
        this.requestCooldowns.set(event, now);
        
        // Limiter les requêtes par seconde
        const requests = this.requestCounts.get(event) || [];
        const recentRequests = requests.filter(time => now - time < 1000);
        
        if (recentRequests.length >= this.maxRequestsPerSecond) {
          if (this.debugMode) {
            console.log(`Rate limit exceeded for event: ${event}`);
          }
          return false;
        }
        
        recentRequests.push(now);
        this.requestCounts.set(event, recentRequests);
      }
      
      if (validateData && !this._validateEventData(event, data)) {
        console.warn(`Invalid data for event: ${event}`);
        return false;
      }
      
      if (this.eventHistory) {
        this.eventHistory.push({
          event,
          data,
          timestamp: Date.now(),
          async
        });
        
        if (this.eventHistory.length > 50) { // Réduit de 100 à 50
          this.eventHistory.shift();
        }
      }
      
      const listeners = this.listeners.get(event) || [];
      
      if (this.debugMode && event === EVENTS.WALLET_INFO_REQUEST) {
        console.log(`Emitting event: ${event} to ${listeners.length} listeners`);
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
    }
  }

  off(event, callbackOrId) {
    const listeners = this.listeners.get(event);
    if (!listeners) return false;
    
    let removed = false;
    
    for (let i = listeners.length - 1; i >= 0; i--) {
      const listener = listeners[i];
      
      if (typeof callbackOrId === 'string' && listener.id === callbackOrId) {
        listeners.splice(i, 1);
        removed = true;
        break;
      } else if (typeof callbackOrId === 'function' && listener.callback === callbackOrId) {
        listeners.splice(i, 1);
        removed = true;
      }
    }
    
    if (listeners.length === 0) {
      this.listeners.delete(event);
    }
    
    if (this.debugMode && removed) {
      console.log(`Event listener removed: ${event}`);
    }
    
    return removed;
  }

  removeAllListeners(event) {
    if (this.listeners.has(event)) {
      const count = this.listeners.get(event).length;
      this.listeners.delete(event);
      
      if (this.debugMode) {
        console.log(`All ${count} listeners removed for event: ${event}`);
      }
    }
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

  cleanup() {
    const now = Date.now();
    const maxAge = 1800000; // Réduit de 3600000 (1h) à 1800000 (30min)
    
    for (const [event, listeners] of this.listeners.entries()) {
      const filteredListeners = listeners.filter(listener => {
        const age = now - listener.created;
        return age <= maxAge;
      });
      
      if (filteredListeners.length === 0) {
        this.listeners.delete(event);
      } else if (filteredListeners.length < listeners.length) {
        this.listeners.set(event, filteredListeners);
      }
    }
    
    if (this.eventHistory) {
      this.eventHistory = this.eventHistory.filter(entry => {
        return (now - entry.timestamp) < maxAge;
      });
    }
    
    // Nettoyage des compteurs de requêtes ET des cooldowns
    for (const [event, requests] of this.requestCounts.entries()) {
      const recentRequests = requests.filter(time => now - time < 5000);
      if (recentRequests.length === 0) {
        this.requestCounts.delete(event);
      } else {
        this.requestCounts.set(event, recentRequests);
      }
    }
    
    // Nettoyer les cooldowns expirés
    for (const [event, lastRequest] of this.requestCooldowns.entries()) {
      if (now - lastRequest > 5000) {
        this.requestCooldowns.delete(event);
      }
    }
    
    if (this.debugMode) {
      console.log('EventMediator cleanup completed');
    }
  }

  _cleanupOldListeners(event) {
    const listeners = this.listeners.get(event) || [];
    const now = Date.now();
    
    // Supprime les listeners de plus de 2 minutes (réduit de 5 minutes)
    const filteredListeners = listeners.filter(listener => {
      return (now - listener.created) < 120000;
    });
    
    // Si encore trop de listeners, garde seulement les plus récents
    if (filteredListeners.length >= this.maxListeners) {
      filteredListeners.sort((a, b) => b.created - a.created);
      filteredListeners.splice(Math.floor(this.maxListeners * 0.7)); // Garde 70% de la limite
    }
    
    this.listeners.set(event, filteredListeners);
    console.log(`Cleaned up listeners for ${event}: ${listeners.length} -> ${filteredListeners.length}`);
  }

  destroy() {
    this.listeners.clear();
    this.requestCounts.clear();
    this.requestCooldowns.clear();
    this.eventCallStack = [];
    
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    
    if (this.eventHistory) {
      this.eventHistory.length = 0;
    }
    
    if (this.debugMode) {
      console.log('EventMediator destroyed');
    }
  }

  // === PRIVATE METHODS ===
  _validateEvent(event, callback) {
    if (typeof event !== 'string' || !event.trim()) {
      console.error('Event name must be a non-empty string');
      return false;
    }
    
    if (typeof callback !== 'function') {
      console.error('Event callback must be a function');
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

  _executeListeners(listeners, eventContext) {
    // Copie la liste pour éviter les modifications pendant l'exécution
    const listenersToExecute = [...listeners];
    
    listenersToExecute.forEach((listener, index) => {
      try {
        listener.callback(eventContext.data, eventContext);
        
        // Supprime les listeners "once" après exécution
        if (listener.once) {
          const originalListeners = this.listeners.get(eventContext.event);
          if (originalListeners) {
            const listenerIndex = originalListeners.findIndex(l => l.id === listener.id);
            if (listenerIndex !== -1) {
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

  _handleError(type, error, context = {}) {
    console.error(`EventMediator ${type} error:`, error, context);
    
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
  maxListeners: 50, // Réduit de 100 à 50
  keepHistory: false
});

// === UTILITY FUNCTIONS ===
export const createEventPromise = (event, timeout = 3000) => {
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

export const waitForEvent = (event, condition = null, timeout = 3000) => {
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

// === CROSS-MODULE COMMUNICATION HELPERS FIXES ===
let walletInfoRequestInProgress = false;
let lastWalletInfoResponse = { address: '', isReady: false };
let walletInfoCooldown = 0;

export const requestWalletInfo = () => {
  const now = Date.now();
  
  // Cooldown de 500ms entre les requêtes
  if (now - walletInfoCooldown < 500) {
    return Promise.resolve(lastWalletInfoResponse);
  }
  
  // Éviter les requêtes multiples simultanées
  if (walletInfoRequestInProgress) {
    return Promise.resolve(lastWalletInfoResponse);
  }
  
  walletInfoRequestInProgress = true;
  walletInfoCooldown = now;
  
  return createEventPromise(EVENTS.WALLET_INFO_RESPONSE, 1000)
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
      }, 10);
    });
};

export const armSecurityTimer = () => {
  eventBus.emit(EVENTS.TIMER_ARM_REQUEST);
};

// === AUTO-CLEANUP ON PAGE UNLOAD ===
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', () => {
    eventBus.destroy();
  });
}

// === GLOBAL ACCESS ===
if (typeof window !== 'undefined') {
  window.eventBus = eventBus;
  window.EVENTS = EVENTS;
}

console.log('Events system loaded with enhanced anti-duplication protection and', Object.keys(EVENTS).length, 'predefined event types');