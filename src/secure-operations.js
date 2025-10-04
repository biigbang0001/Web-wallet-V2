import { getTranslation } from './config.js';

// === SECURE KEY OPERATIONS ===

/**
 * Execute an operation with a private key, ensuring automatic cleanup
 * @param {Function} operation - Async function that receives the keyPair
 * @returns {Promise<any>} Result of the operation
 */
export async function executeWithPrivateKey(operation) {
  let privateKey = null;
  let keyPair = null;
  
  try {
    if (!window.keyManager) {
      throw new Error(getTranslation('wallet.keymanager_not_initialized', 'KeyManager not initialized'));
    }
    
    privateKey = await window.keyManager.retrieveKey('private_key');
    if (!privateKey) {
      throw new Error(getTranslation('wallet.private_key_not_found', 'Private key not found'));
    }
    
    const pkBuffer = typeof privateKey === 'string' 
      ? Buffer.from(privateKey, 'hex')
      : Buffer.from(privateKey);
      
    if (!window.ECPair) {
      throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library unavailable'));
    }
    
    keyPair = window.ECPair.fromPrivateKey(pkBuffer, { network: window.NITO_NETWORK });
    
    // Security: Clear the temporary buffer immediately
    pkBuffer.fill(0);
    
    // Execute the operation
    const result = await operation(keyPair);
    
    return result;
    
  } finally {
    // Security: Systematic cleanup
    if (keyPair?.privateKey) {
      try {
        if (Buffer.isBuffer(keyPair.privateKey)) {
          keyPair.privateKey.fill(0);
        } else if (keyPair.privateKey instanceof Uint8Array) {
          keyPair.privateKey.fill(0);
        }
      } catch (e) {}
    }
    
    if (privateKey) {
      if (Buffer.isBuffer(privateKey)) {
        try {
          privateKey.fill(0);
        } catch (e) {}
      } else if (privateKey instanceof Uint8Array) {
        try {
          privateKey.fill(0);
        } catch (e) {}
      }
    }
    
    // Security: Force release references
    privateKey = null;
    keyPair = null;
    
    // Security: Hint for garbage collection if available
    if (typeof window !== 'undefined' && window.gc) {
      try { window.gc(); } catch(e) {}
    }
  }
}

/**
 * Execute an operation with an HD wallet key, ensuring automatic cleanup
 * @param {string} derivationPath - The derivation path to use
 * @param {Function} operation - Async function that receives the keyPair
 * @returns {Promise<any>} Result of the operation
 */
export async function executeWithHDKey(derivationPath, operation) {
  let keyPair = null;
  
  try {
    if (!window.hdManager) {
      throw new Error(getTranslation('wallet.hd_wallet_not_initialized', 'HD wallet not initialized'));
    }
    
    if (derivationPath === 'taproot') {
      keyPair = await window.hdManager.getTaprootKeyPair();
    } else {
      keyPair = await window.hdManager.getKeyPair();
    }
    
    if (!keyPair) {
      throw new Error(getTranslation('wallet.keypair_derivation_failed', 'Failed to derive keypair'));
    }
    
    // Execute the operation
    const result = await operation(keyPair);
    
    return result;
    
  } finally {
    // Security: Systematic cleanup
    if (keyPair?.privateKey) {
      try {
        if (Buffer.isBuffer(keyPair.privateKey)) {
          keyPair.privateKey.fill(0);
        } else if (keyPair.privateKey instanceof Uint8Array) {
          keyPair.privateKey.fill(0);
        }
      } catch (e) {}
    }
    
    // Security: Force release reference
    keyPair = null;
    
    // Security: Hint for garbage collection if available
    if (typeof window !== 'undefined' && window.gc) {
      try { window.gc(); } catch(e) {}
    }
  }
}

/**
 * Execute a signing operation with automatic key cleanup
 * @param {Object} hash - The hash to sign
 * @param {string} keyType - Type of key to use ('single' or 'hd')
 * @param {string} addressType - Address type ('bech32' or 'taproot')
 * @returns {Promise<Buffer>} The signature
 */
export async function executeSignature(hash, keyType = 'single', addressType = 'bech32') {
  if (keyType === 'hd' && window.hdManager) {
    return await executeWithHDKey(addressType === 'taproot' ? 'taproot' : 'bech32', async (keyPair) => {
      const signature = keyPair.sign(hash);
      return Buffer.from(signature);
    });
  } else {
    return await executeWithPrivateKey(async (keyPair) => {
      const signature = keyPair.sign(hash);
      return Buffer.from(signature);
    });
  }
}

/**
 * Clean up a buffer or Uint8Array
 * @param {Buffer|Uint8Array|any} data - Data to clean
 */
export function cleanupSensitiveData(data) {
  if (!data) return;
  
  try {
    if (Buffer.isBuffer(data)) {
      data.fill(0);
    } else if (data instanceof Uint8Array) {
      data.fill(0);
    } else if (typeof data === 'object' && data.privateKey) {
      // Handle keyPair objects
      cleanupSensitiveData(data.privateKey);
    }
  } catch (e) {
    // Silently fail if cleanup fails
  }
}

/**
 * Clean up an array of sensitive data
 * @param {Array} dataArray - Array of data to clean
 */
export function cleanupSensitiveArray(dataArray) {
  if (!Array.isArray(dataArray)) return;
  
  dataArray.forEach(data => {
    cleanupSensitiveData(data);
  });
}

/**
 * Execute an operation with a timeout and automatic cleanup
 * @param {Function} operation - Async operation to execute
 * @param {number} timeoutMs - Timeout in milliseconds
 * @returns {Promise<any>} Result of the operation
 */
export async function executeWithTimeout(operation, timeoutMs = 30000) {
  let timeoutId = null;
  
  try {
    const timeoutPromise = new Promise((_, reject) => {
      timeoutId = setTimeout(() => {
        reject(new Error(getTranslation('security.operation_timeout', 'Operation timeout')));
      }, timeoutMs);
    });
    
    const result = await Promise.race([
      operation(),
      timeoutPromise
    ]);
    
    return result;
    
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  }
}

/**
 * Verify that sensitive data has been properly cleaned
 * @param {any} data - Data to verify
 * @returns {boolean} True if data appears to be cleaned
 */
export function verifyCleaned(data) {
  if (!data) return true;
  
  try {
    if (Buffer.isBuffer(data) || data instanceof Uint8Array) {
      // Check if all bytes are zero
      for (let i = 0; i < data.length; i++) {
        if (data[i] !== 0) return false;
      }
      return true;
    }
    return false;
  } catch (e) {
    return false;
  }
}

// === SECURE TRANSACTION WRAPPER ===

/**
 * Build and sign a transaction with automatic key cleanup
 * @param {Object} params - Transaction parameters
 * @returns {Promise<Object>} Transaction result
 */
export async function secureTransaction(params) {
  const {
    destinationAddress,
    amountSats,
    selectedUtxos,
    isConsolidation = false,
    sourceType = 'bech32',
    isMaxSend = false
  } = params;
  
  if (!window.TransactionBuilder) {
    throw new Error(getTranslation('errors.transaction_functions_unavailable', 'Transaction functions unavailable'));
  }
  
  const transactionBuilder = new window.TransactionBuilder();
  
  // Use the existing transaction builder but ensure cleanup happens
  try {
    const result = await transactionBuilder.buildAndSignTransaction(
      destinationAddress,
      amountSats,
      selectedUtxos,
      isConsolidation,
      sourceType,
      isMaxSend
    );
    
    return result;
    
  } finally {
    // Additional cleanup layer
    if (typeof window !== 'undefined' && window.gc) {
      try { window.gc(); } catch(e) {}
    }
  }
}

// === GLOBAL EXPORTS ===
if (typeof window !== 'undefined') {
  window.executeWithPrivateKey = executeWithPrivateKey;
  window.executeWithHDKey = executeWithHDKey;
  window.executeSignature = executeSignature;
  window.cleanupSensitiveData = cleanupSensitiveData;
  window.cleanupSensitiveArray = cleanupSensitiveArray;
  window.executeWithTimeout = executeWithTimeout;
  window.verifyCleaned = verifyCleaned;
  window.secureTransaction = secureTransaction;
}

export default {
  executeWithPrivateKey,
  executeWithHDKey,
  executeSignature,
  cleanupSensitiveData,
  cleanupSensitiveArray,
  executeWithTimeout,
  verifyCleaned,
  secureTransaction
};