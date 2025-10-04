import { HD_CONFIG, NITO_NETWORK, getTranslation } from './config.js';
import { eventBus, EVENTS } from './events.js';
import { armInactivityTimerSafely, validateInput, deriveFromCredentials } from './security.js';
import { getBitcoinLibraries } from './vendor.js';
import { utxos, balance, AddressManager, TaprootUtils } from './blockchain.js';
import { showBalanceLoadingSpinner } from './ui-popups.js';

// === GLOBAL REFRESH RATE LIMITING ===
let lastGlobalRefresh = 0;
const GLOBAL_REFRESH_COOLDOWN = 10000;

function canRefreshGlobally() {
  const now = Date.now();
  const timeSinceLastRefresh = now - lastGlobalRefresh;
  
  if (timeSinceLastRefresh < GLOBAL_REFRESH_COOLDOWN) {
    return false;
  }
  
  return true;
}

// === HD WALLET MANAGER ===
export class HDWalletManager {
  constructor(hdWallet) {
    this.publicKeyCache = new Map();
    this.initializeEncryption(hdWallet);
  }

  async initializeEncryption(hdWallet) {
    let attempts = 0;
    while (!window.keyManager && attempts < 50) {
      await new Promise(resolve => setTimeout(resolve, 100));
      attempts++;
    }
    
    if (!window.keyManager) {
      if (window.initializeSecurity) {
        try {
          window.keyManager = await window.initializeSecurity();
        } catch (error) {
          console.error('[WALLET] Failed to initialize keyManager:', error);
          throw new Error('KeyManager initialization failed');
        }
      }
      if (!window.keyManager) {
        throw new Error('KeyManager not available after waiting');
      }
    }

    const xprv = hdWallet.toBase58();
    await window.keyManager.storeKey('hd_xprv', xprv);
  }

  async getHDWallet() {
    if (!window.keyManager) {
      if (window.initializeSecurity) {
        window.keyManager = await window.initializeSecurity();
      }
      if (!window.keyManager) {
        throw new Error(getTranslation('wallet.keymanager_not_initialized', 'KeyManager not initialized'));
      }
    }

    const xprv = await window.keyManager.retrieveKey('hd_xprv');
    if (!xprv) {
      throw new Error(getTranslation('wallet.hd_wallet_not_found', 'HD wallet not found'));
    }

    if (!window.bip32) {
      throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library unavailable'));
    }

    return window.bip32.fromBase58(xprv, NITO_NETWORK);
  }

  async getKeyPair() {
    const hdWallet = await this.getHDWallet();
    const account = hdWallet.derivePath(HD_CONFIG.DERIVATION_PATHS.bech32);
    const child = account.derive(0).derive(0);
    
    if (!window.ECPair) {
      throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library unavailable'));
    }

    const keyPair = window.ECPair.fromPrivateKey(child.privateKey, { network: NITO_NETWORK });
    
    return keyPair;
  }

  async getTaprootKeyPair() {
    const hdWallet = await this.getHDWallet();
    const account = hdWallet.derivePath(HD_CONFIG.DERIVATION_PATHS.taproot);
    const child = account.derive(0).derive(0);
    
    if (!window.ECPair) {
      throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library unavailable'));
    }

    const keyPair = window.ECPair.fromPrivateKey(child.privateKey, { network: NITO_NETWORK });
    
    return keyPair;
  }

  async getKeyPairByPath(path) {
    const hdWallet = await this.getHDWallet();
    const account = hdWallet.derivePath(path);
    const child = account.derive(0).derive(0);
    
    if (!window.ECPair) {
      throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library unavailable'));
    }
    
    const keyPair = window.ECPair.fromPrivateKey(child.privateKey, { network: NITO_NETWORK });
    return keyPair;
  }

  async getPublicKey() {
    if (this.publicKeyCache.has('bech32')) {
      return this.publicKeyCache.get('bech32');
    }

    const keyPair = await this.getKeyPair();
    const publicKey = keyPair.publicKey;
    this.publicKeyCache.set('bech32', publicKey);
    
    if (keyPair.privateKey) {
      try {
        if (Buffer.isBuffer(keyPair.privateKey)) {
          keyPair.privateKey.fill(0);
        } else if (keyPair.privateKey instanceof Uint8Array) {
          keyPair.privateKey.fill(0);
        }
      } catch (e) {}
    }
    
    return publicKey;
  }

  async getTaprootPublicKey() {
    if (this.publicKeyCache.has('taproot')) {
      return this.publicKeyCache.get('taproot');
    }

    const keyPair = await this.getTaprootKeyPair();
    const publicKey = keyPair.publicKey;
    this.publicKeyCache.set('taproot', publicKey);
    
    if (keyPair.privateKey) {
      try {
        if (Buffer.isBuffer(keyPair.privateKey)) {
          keyPair.privateKey.fill(0);
        } else if (keyPair.privateKey instanceof Uint8Array) {
          keyPair.privateKey.fill(0);
        }
      } catch (e) {}
    }
    
    return publicKey;
  }

  clearCaches() {
    this.publicKeyCache.clear();
  }
}

// === WALLET INFO ===
export async function getWalletInfo() {
  if (window.isWalletReady && window.isWalletReady()) {
    return {
      address: window.getWalletAddress ? window.getWalletAddress() : '',
      isReady: true,
      importType: window.importType || 'single',
      addresses: {
        bech32: window.bech32Address || '',
        legacy: window.legacyAddress || '',
        p2sh: window.p2shAddress || '',
        taproot: window.taprootAddress || ''
      }
    };
  }

  return { 
    address: '', 
    isReady: false, 
    importType: null,
    addresses: {} 
  };
}

// === GENERATE HD WALLET ===
export async function generateHDWallet(wordCount = 24) {
  let seed = null;
  try {
    armInactivityTimerSafely();

    if (!window.bip39 || !window.bip32) {
      throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library unavailable'));
    }

    const entropyBits = wordCount === 24 ? 256 : 128;
    const mnemonic = window.bip39.generateMnemonic(entropyBits);
    
    if (!window.bip39.validateMnemonic(mnemonic)) {
      throw new Error(getTranslation('wallet.invalid_mnemonic', 'Invalid mnemonic phrase'));
    }

    seed = await window.bip39.mnemonicToSeed(mnemonic);
    const hdWallet = window.bip32.fromSeed(seed, NITO_NETWORK);

    const addresses = await deriveAllAddresses(hdWallet);

    window.hdManager = new HDWalletManager(hdWallet);
    window.importType = 'hd';
    window.bech32Address = addresses.bech32;
    window.legacyAddress = addresses.legacy;
    window.p2shAddress = addresses.p2sh;
    window.taprootAddress = addresses.taproot;

    await window.keyManager.storeKey('mnemonic', mnemonic);
    
    console.log('=== WALLET ADDRESSES (HD) ===');
    console.log('Bech32 (Native) :', addresses.bech32);
    console.log('Bech32m (Taproot):', addresses.taproot);
    console.log('Legacy (P2PKH)  :', addresses.legacy);
    console.log('P2SH (Wrapped)  :', addresses.p2sh);
    console.log('============================');

    return { addresses };

  } catch (error) {
    console.error(`[WALLET] ${getTranslation('wallet.failed_to_generate_mnemonic', 'Failed to generate mnemonic phrase')}`, error);
    throw error;
  } finally {
    if (seed?.fill) {
      seed.fill(0);
    }
  }
}

// === DERIVE ALL ADDRESSES ===
async function deriveAllAddresses(hdWallet) {
  if (!window.bitcoin || !window.ECPair) {
    throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library unavailable'));
  }

  const addresses = {};

  for (const [family, path] of Object.entries(HD_CONFIG.DERIVATION_PATHS)) {
    let keyPair = null;
    try {
      const account = hdWallet.derivePath(path);
      const child = account.derive(0).derive(0);
      keyPair = window.ECPair.fromPrivateKey(child.privateKey, { network: NITO_NETWORK });
      const pubkey = Buffer.from(keyPair.publicKey);

      switch (family) {
        case 'legacy':
          addresses.legacy = window.bitcoin.payments.p2pkh({ pubkey, network: NITO_NETWORK }).address;
          break;

        case 'p2sh':
          const p2wpkh = window.bitcoin.payments.p2wpkh({ pubkey, network: NITO_NETWORK });
          addresses.p2sh = window.bitcoin.payments.p2sh({ redeem: p2wpkh, network: NITO_NETWORK }).address;
          break;

        case 'bech32':
          addresses.bech32 = window.bitcoin.payments.p2wpkh({ pubkey, network: NITO_NETWORK }).address;
          break;

        case 'taproot':
          const internalKey = pubkey.slice(1, 33);
          addresses.taproot = window.bitcoin.payments.p2tr({ internalPubkey: internalKey, network: NITO_NETWORK }).address;
          break;
      }
    } catch (error) {
      console.error(`[WALLET] ${getTranslation('wallet.failed_to_derive_addresses', 'Failed to derive addresses: {{error}}', {error: error.message})}`, family);
    } finally {
      if (keyPair?.privateKey) {
        try {
          if (Buffer.isBuffer(keyPair.privateKey)) {
            keyPair.privateKey.fill(0);
          } else if (keyPair.privateKey instanceof Uint8Array) {
            keyPair.privateKey.fill(0);
          }
        } catch (e) {}
      }
    }
  }

  return addresses;
}

// === IMPORT HD WALLET ===
export async function importHDWallet(input) {
  let seed = null;
  try {
    armInactivityTimerSafely();

    if (!window.bip39 || !window.bip32) {
      throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library unavailable'));
    }

    let hdWallet;
    const trimmedInput = input.trim();
    let shouldStoreMnemonic = false;

    if (trimmedInput.startsWith('xprv')) {
      validateInput(trimmedInput, 'xprv');
      hdWallet = window.bip32.fromBase58(trimmedInput, NITO_NETWORK);
    } else {
      const words = trimmedInput.split(/\s+/);
      if (words.length !== 12 && words.length !== 24) {
        throw new Error(getTranslation('wallet.invalid_mnemonic', 'Invalid mnemonic phrase'));
      }

      if (!window.bip39.validateMnemonic(trimmedInput)) {
        throw new Error(getTranslation('wallet.invalid_mnemonic', 'Invalid mnemonic phrase'));
      }

      seed = await window.bip39.mnemonicToSeed(trimmedInput);
      hdWallet = window.bip32.fromSeed(seed, NITO_NETWORK);
      shouldStoreMnemonic = true;
    }

    const addresses = await deriveAllAddresses(hdWallet);
    addresses.hdWallet = hdWallet;

    if (shouldStoreMnemonic && window.keyManager) {
      await window.keyManager.storeKey('mnemonic', trimmedInput);
    }

    return addresses;

  } catch (error) {
    console.error(`[WALLET] ${getTranslation('wallet.hd_wallet_import_failed', 'HD wallet import failed: {{error}}', {error: error.message})}`);
    throw error;
  } finally {
    if (seed?.fill) {
      seed.fill(0);
    }
  }
}

// === IMPORT SINGLE KEY WALLET ===
export async function importSingleKeyWallet(privateKeyInput) {
  let keyPair = null;
  let privateKeyBuffer = null;
  try {
    armInactivityTimerSafely();

    if (!window.bitcoin || !window.ECPair) {
      throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library unavailable'));
    }

    const trimmedInput = privateKeyInput.trim();

    if (/^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(trimmedInput)) {
      validateInput(trimmedInput, 'wif');
      keyPair = window.ECPair.fromWIF(trimmedInput, NITO_NETWORK);
    } else if (/^[0-9a-fA-F]{64}$/.test(trimmedInput)) {
      validateInput(trimmedInput, 'hex');
      privateKeyBuffer = Buffer.from(trimmedInput, 'hex');
      
      if (privateKeyBuffer.length !== 32) {
        throw new Error(getTranslation('security.private_key_32_bytes', 'Private key must be 32 bytes'));
      }
      
      keyPair = window.ECPair.fromPrivateKey(privateKeyBuffer, { network: NITO_NETWORK });
    } else {
      throw new Error(getTranslation('wallet.unsupported_input_format', 'Unsupported input format'));
    }

    const pubkey = Buffer.from(keyPair.publicKey);

    const bech32Address = window.bitcoin.payments.p2wpkh({ pubkey, network: NITO_NETWORK }).address;
    const legacyAddress = window.bitcoin.payments.p2pkh({ pubkey, network: NITO_NETWORK }).address;
    
    const p2wpkhPayment = window.bitcoin.payments.p2wpkh({ pubkey, network: NITO_NETWORK });
    const p2shAddress = window.bitcoin.payments.p2sh({ redeem: p2wpkhPayment, network: NITO_NETWORK }).address;

    const internalKey = pubkey.slice(1, 33);
    const taprootAddress = window.bitcoin.payments.p2tr({ internalPubkey: internalKey, network: NITO_NETWORK }).address;

    if (window.keyManager) {
      await window.keyManager.storeKey('private_key', keyPair.privateKey);
      await window.keyManager.storeKey('public_key', keyPair.publicKey);
    }

    return {
      bech32: bech32Address,
      legacy: legacyAddress,
      p2sh: p2shAddress,
      taproot: taprootAddress
    };

  } catch (error) {
    console.error(`[WALLET] ${getTranslation('errors.import_error', 'Import error')}`, error);
    throw error;
  } finally {
    if (privateKeyBuffer && Buffer.isBuffer(privateKeyBuffer)) {
      privateKeyBuffer.fill(0);
    }
    if (keyPair?.privateKey) {
      try {
        if (Buffer.isBuffer(keyPair.privateKey)) {
          keyPair.privateKey.fill(0);
        } else if (keyPair.privateKey instanceof Uint8Array) {
          keyPair.privateKey.fill(0);
        }
      } catch (e) {}
    }
  }
}

// === IMPORT WALLET ===
export async function importWallet(arg1, arg2) {
  let seed = null;
  try {
    if (typeof arg2 === 'string' && typeof arg1 === 'string') {
      const email = arg1.trim().toLowerCase();
      const password = arg2.trim();
      
      if (!email || !password) {
        throw new Error(getTranslation('security.empty_input', 'Empty input provided'));
      }

      validateInput(email, 'email');

      console.log(`[WALLET] ${getTranslation('wallet.email_connection_started', 'Email sign-in started, generating wallet...')}`);

      const mnemonic = await deriveFromCredentials(email, password, 24);
      
      if (!window.bip39 || !window.bip32) {
        throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library unavailable'));
      }

      if (!window.bip39.validateMnemonic(mnemonic)) {
        throw new Error(getTranslation('wallet.invalid_mnemonic', 'Invalid mnemonic phrase'));
      }

      console.log(`[WALLET] ${getTranslation('wallet.email_wallet_generated', 'Email wallet generated, calculating balances...')}`);

      seed = await window.bip39.mnemonicToSeed(mnemonic);
      const hdWallet = window.bip32.fromSeed(seed, NITO_NETWORK);

      const addresses = await deriveAllAddresses(hdWallet);

      window.hdManager = new HDWalletManager(hdWallet);
      window.importType = 'hd';
      window.bech32Address = addresses.bech32;
      window.legacyAddress = addresses.legacy;
      window.p2shAddress = addresses.p2sh;
      window.taprootAddress = addresses.taproot;

      await window.keyManager.storeKey('mnemonic', mnemonic);

      console.log(`[WALLET] ${getTranslation('wallet.email_wallet_connected', 'Email wallet connected successfully ({{words}} words)', {words: 24})}`);
      console.log('=== WALLET ADDRESSES (HD) ===');
      console.log('Bech32 (Native) :', addresses.bech32);
      console.log('Bech32m (Taproot):', addresses.taproot);
      console.log('Legacy (P2PKH)  :', addresses.legacy);
      console.log('P2SH (Wrapped)  :', addresses.p2sh);
      console.log('============================');

      return {
        success: true,
        addresses,
        importType: 'email'
      };

    } else {
      const input = (arg1 || '').toString().trim();
      if (!input) {
        throw new Error(getTranslation('security.empty_input', 'Empty input provided'));
      }
      
      let addresses;
      let importType;
      
      if (input.startsWith('xprv')) {
        validateInput(input, 'xprv');
        const result = await importHDWallet(input);
        addresses = result;
        importType = 'xprv';
        window.hdManager = new HDWalletManager(result.hdWallet);
        window.importType = 'hd';
      } 
      else if (input.split(/\s+/).length === 12 || input.split(/\s+/).length === 24) {
        const result = await importHDWallet(input);
        addresses = result;
        importType = 'mnemonic';
        window.hdManager = new HDWalletManager(result.hdWallet);
        window.importType = 'hd';
      }
      else if (/^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(input)) {
        validateInput(input, 'wif');
        addresses = await importSingleKeyWallet(input);
        importType = 'wif';
        window.importType = 'single';
      }
      else if (/^[0-9a-fA-F]{64}$/.test(input)) {
        validateInput(input, 'hex');
        addresses = await importSingleKeyWallet(input);
        importType = 'hex';
        window.importType = 'single';
      }
      else {
        throw new Error(getTranslation('wallet.unsupported_input_format', 'Unsupported input format'));
      }
      
      window.legacyAddress = addresses.legacy;
      window.p2shAddress = addresses.p2sh;
      window.bech32Address = addresses.bech32;
      window.taprootAddress = addresses.taproot || '';
      
      eventBus.emit(EVENTS.WALLET_IMPORTED, { addresses, importType });
      
      console.log(`[WALLET] Wallet imported successfully (${importType})`);
      
      if (window.importType === 'hd') {
        console.log('=== WALLET ADDRESSES (HD) ===');
        console.log('Bech32 (Native) :', addresses.bech32);
        console.log('Bech32m (Taproot):', addresses.taproot);
        console.log('Legacy (P2PKH)  :', addresses.legacy);
        console.log('P2SH (Wrapped)  :', addresses.p2sh);
        console.log('============================');
      } else {
        console.log('=== WALLET ADDRESSES (Single Key) ===');
        console.log('Bech32 (Native) :', addresses.bech32);
        console.log('Legacy (P2PKH)  :', addresses.legacy);
        console.log('P2SH (Wrapped)  :', addresses.p2sh);
        console.log('=====================================');
      }
      
      return { 
        success: true, 
        importType,
        addresses
      };
    }
  } catch (error) {
    console.error(`[WALLET] ${getTranslation('errors.import_error', 'Import error')}`, error);
    return { 
      success: false, 
      error: error.message || String(error) 
    };
  } finally {
    if (seed?.fill) {
      seed.fill(0);
    }
  }
}

// === CONNECT WITH EMAIL ===
export async function connectWithEmail(email, password, wordCount = 24) {
  return await importWallet(email, password);
}

// === GET TOTAL BALANCE ===
export async function getTotalBalance() {
  try {
    const isHD = window.importType === 'hd';
    const hdWallet = isHD && window.hdManager ? await window.hdManager.getHDWallet() : null;

    let totalBalance = 0;

    if (window.bech32Address) {
      const bech32Balance = await balance(window.bech32Address, isHD, hdWallet);
      totalBalance += bech32Balance;
    }

    if (window.taprootAddress && isHD) {
      const taprootBalance = await balance(window.taprootAddress, true, hdWallet);
      totalBalance += taprootBalance;
    }

    return totalBalance;

  } catch (error) {
    console.error(`[WALLET] ${getTranslation('ui.refresh_error', 'Refresh error: {{error}}', {error: error.message})}`);
    return 0;
  }
}

// === REFRESH ALL BALANCES ===
export async function refreshAllBalances() {
  if (!canRefreshGlobally()) {
    return;
  }
  
  if (window.isOperationActive && window.isOperationActive('full-refresh')) {
    return;
  }
  
  lastGlobalRefresh = Date.now();
  
  if (window.startOperation) window.startOperation('full-refresh');
  
  try {
    showBalanceLoadingSpinner(true, 'loading.cache_clearing');
    
    if (window.CacheManager) {
      const walletInfo = await getWalletInfo();
      window.CacheManager.invalidateAll();
    }
    
    await new Promise(r => setTimeout(r, 800));
    
    showBalanceLoadingSpinner(true, 'loading.utxo_scan');
    
    const isHD = window.importType === 'hd';
    const hdWallet = isHD && window.hdManager ? await window.hdManager.getHDWallet() : null;

    let totalBalance = 0;

    if (window.bech32Address) {
      const bech32Balance = await balance(window.bech32Address, isHD, hdWallet);
      totalBalance += bech32Balance;
    }

    if (window.taprootAddress && isHD) {
      const taprootBalance = await balance(window.taprootAddress, true, hdWallet);
      totalBalance += taprootBalance;
    }

    const balanceElement = document.getElementById('totalBalance');
    if (balanceElement) {
      const balanceText = getTranslation('import_section.balance', 'Balance:');
      balanceElement.textContent = `${balanceText} ${totalBalance.toFixed(8)} NITO`;
    }
    
    const sendTabBalance = document.getElementById('sendTabBalance');
    if (sendTabBalance) {
      const selectedType = document.getElementById('debitAddressType')?.value || 'bech32';
      
      if (selectedType === 'p2tr' && window.taprootAddress && isHD) {
        const cacheKey = `balance:${window.taprootAddress}:true`;
        const cached = window.SMART_BALANCE_CACHE?.get?.(cacheKey);
        if (cached !== null && cached !== undefined) {
          sendTabBalance.textContent = cached.toFixed(8);
        }
      } else if (window.bech32Address) {
        const cacheKey = `balance:${window.bech32Address}:${isHD}`;
        const cached = window.SMART_BALANCE_CACHE?.get?.(cacheKey);
        if (cached !== null && cached !== undefined) {
          sendTabBalance.textContent = cached.toFixed(8);
        }
      }
    }
    
    showBalanceLoadingSpinner(true, 'loading.balance_updated');
    await new Promise(r => setTimeout(r, 1200));
    
  } catch (error) {
    console.error(`[REFRESH] ${getTranslation('ui.refresh_error', 'Refresh error: {{error}}', {error: error.message})}`);
    showBalanceLoadingSpinner(true, 'loading.update_error');
    await new Promise(r => setTimeout(r, 1500));
  } finally {
    showBalanceLoadingSpinner(false);
    if (window.endOperation) window.endOperation('full-refresh');
  }
}

// === WALLET STATUS ===
export function isWalletReady() {
  return !!(window.bech32Address || window.taprootAddress);
}

export function getWalletAddress() {
  return window.bech32Address || '';
}

export function getTaprootAddress() {
  return window.taprootAddress || '';
}

// === KEYPAIRS ===
export async function getWalletKeyPair() {
  let keyPair = null;
  let pkBuffer = null;
  try {
    if (window.importType === 'hd' && window.hdManager) {
      keyPair = await window.hdManager.getKeyPair();
    } else if (window.keyManager) {
      const privateKey = await window.keyManager.retrieveKey('private_key');
      if (privateKey && window.ECPair) {
        pkBuffer = typeof privateKey === 'string' 
          ? Buffer.from(privateKey, 'hex')
          : Buffer.from(privateKey);
        keyPair = window.ECPair.fromPrivateKey(pkBuffer, { network: NITO_NETWORK });
      }
    }
    
    return keyPair;
  } catch (error) {
    throw error;
  } finally {
    if (pkBuffer && Buffer.isBuffer(pkBuffer)) {
      pkBuffer.fill(0);
    }
  }
}

export async function getTaprootKeyPair() {
  let keyPair = null;
  let pkBuffer = null;
  try {
    if (window.importType === 'hd' && window.hdManager) {
      keyPair = await window.hdManager.getTaprootKeyPair();
    } else if (window.keyManager) {
      const privateKey = await window.keyManager.retrieveKey('private_key');
      if (privateKey && window.ECPair) {
        pkBuffer = typeof privateKey === 'string'
          ? Buffer.from(privateKey, 'hex')
          : Buffer.from(privateKey);
        keyPair = window.ECPair.fromPrivateKey(pkBuffer, { network: NITO_NETWORK });
      }
    }
    
    return keyPair;
  } catch (error) {
    throw error;
  } finally {
    if (pkBuffer && Buffer.isBuffer(pkBuffer)) {
      pkBuffer.fill(0);
    }
  }
}

export async function getWalletPublicKey() {
  if (window.importType === 'hd' && window.hdManager) {
    return await window.hdManager.getPublicKey();
  } else if (window.keyManager) {
    return await window.keyManager.retrieveKey('public_key');
  }
  return null;
}

export async function getTaprootPublicKey() {
  if (window.importType === 'hd' && window.hdManager) {
    return await window.hdManager.getTaprootPublicKey();
  } else if (window.keyManager) {
    return await window.keyManager.retrieveKey('public_key');
  }
  return null;
}

// === EVENT LISTENERS ===
eventBus.on(EVENTS.WALLET_INFO_REQUEST, async () => {
  const walletInfo = await getWalletInfo();
  eventBus.emit(EVENTS.WALLET_INFO_RESPONSE, walletInfo);
});

// === GLOBAL EXPORTS ===
if (typeof window !== 'undefined') {
  window.generateHDWallet = generateHDWallet;
  window.importHDWallet = importHDWallet;
  window.importSingleKeyWallet = importSingleKeyWallet;
  window.importWallet = importWallet;
  window.connectWithEmail = connectWithEmail;
  window.getTotalBalance = getTotalBalance;
  window.refreshAllBalances = refreshAllBalances;
  window.isWalletReady = isWalletReady;
  window.getWalletAddress = getWalletAddress;
  window.getTaprootAddress = getTaprootAddress;
  window.getWalletKeyPair = getWalletKeyPair;
  window.getTaprootKeyPair = getTaprootKeyPair;
  window.getWalletPublicKey = getWalletPublicKey;
  window.getTaprootPublicKey = getTaprootPublicKey;
  window.getWalletInfo = getWalletInfo;
}

export default HDWalletManager;