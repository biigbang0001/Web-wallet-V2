// Blockchain Operations for NITO Wallet
// Handles RPC communication, UTXO management, and blockchain queries

import { NODE_CONFIG, HD_CONFIG, TRANSACTION_CONFIG, VALIDATION_PATTERNS, NITO_NETWORK, getTranslation } from './config.js';
import { eventBus, EVENTS, requestWalletInfo } from './events.js';

// === CACHING AND STATE ===
const RAW_TX_CACHE = new Map();
const UTXO_CACHE = new Map();
const BALANCE_CACHE = new Map();

const CACHE_CONFIG = {
  UTXO: {
    DURATION: 300000,
    MAX_SIZE: 50,
    PRIORITY: 'high'
  },
  BALANCE: {
    DURATION: 30000,
    MAX_SIZE: 20,
    PRIORITY: 'normal'
  },
  RAW_TX: {
    DURATION: 300000,
    MAX_SIZE: 100,
    PRIORITY: 'low'
  }
};

class SmartCache {
  constructor(config) {
    this.cache = new Map();
    this.config = config;
  }

  set(key, value) {
    if (this.cache.size >= this.config.MAX_SIZE) {
      this.cleanup();
    }
    
    this.cache.set(key, {
      data: value,
      timestamp: Date.now(),
      hits: 0
    });
  }

  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;

    const age = Date.now() - entry.timestamp;
    if (age > this.config.DURATION) {
      this.cache.delete(key);
      return null;
    }

    entry.hits++;
    return entry.data;
  }

  has(key) {
    return this.get(key) !== null;
  }

  cleanup() {
    if (this.config.PRIORITY === 'high') {
      const now = Date.now();
      for (const [key, entry] of this.cache.entries()) {
        if (now - entry.timestamp > this.config.DURATION) {
          this.cache.delete(key);
        }
      }
      return;
    }

    const entries = Array.from(this.cache.entries())
      .sort((a, b) => a[1].hits - b[1].hits)
      .slice(0, Math.floor(this.config.MAX_SIZE * 0.3));
    
    entries.forEach(([key]) => this.cache.delete(key));
  }

  clear(selective = false) {
    if (selective && this.config.PRIORITY === 'high') {
      return;
    }
    this.cache.clear();
  }

  invalidate(key) {
    this.cache.delete(key);
  }
}

const SMART_UTXO_CACHE = new SmartCache(CACHE_CONFIG.UTXO);
const SMART_BALANCE_CACHE = new SmartCache(CACHE_CONFIG.BALANCE);
const SMART_TX_CACHE = new SmartCache(CACHE_CONFIG.RAW_TX);

// === UTILITY FUNCTIONS ===
function sleep(ms) { 
  return new Promise(resolve => setTimeout(resolve, ms)); 
}

async function sleepJitter(baseMs = 1, maxJitterMs = 300, active = false) {
  const extra = active ? Math.floor(Math.random() * (maxJitterMs + 1)) : 0;
  await sleep(baseMs + extra);
}

// === UNIFIED ERROR HANDLING ===
export async function handleError500WithRetry(operation, maxRetries = 3) {
  let attempt = 0;
  
  while (attempt < maxRetries) {
    try {
      return await operation();
    } catch (error) {
      const errorMsg = String(error.message || error);
      
      if (errorMsg.includes('500') || errorMsg.includes('Internal Server Error') || errorMsg.includes('Scan already in progress')) {
        attempt++;
        
        if (errorMsg.includes('Scan already in progress')) {
          try {
            await rpcClient.call('scantxoutset', ['abort']);
            await sleep(1000);
          } catch (abortError) {
            console.warn('Failed to abort existing scan:', abortError);
          }
        }
        
        if (attempt < maxRetries) {
          await sleep(NODE_CONFIG.ERROR_500_DELAY);
          continue;
        } else {
          console.error(`[BLOCKCHAIN] Operation failed after ${maxRetries} attempts`);
        }
      }
      
      throw error;
    }
  }
}

// === SECURE RPC CLIENT ===
export class SecureRPCClient {
  constructor(nodeUrl = NODE_CONFIG.URL) {
    this.nodeUrl = nodeUrl;
    this.cache = new Map();
    this.requestQueue = new Map();
    this.debug = NODE_CONFIG.DEBUG;
    this.requestId = 1;
  }

  async call(method, params = []) {
    const cacheKey = `${method}:${JSON.stringify(params)}`;
    
    if (this.shouldCache(method) && this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.getCacheDuration(method)) {
        return cached.data;
      }
      this.cache.delete(cacheKey);
    }

    if (this.requestQueue.has(cacheKey)) {
      return this.requestQueue.get(cacheKey);
    }

    const promise = this.executeRequest(method, params);
    this.requestQueue.set(cacheKey, promise);

    try {
      const result = await promise;
      
      if (this.shouldCache(method)) {
        this.cache.set(cacheKey, {
          data: result,
          timestamp: Date.now()
        });
        
        if (this.cache.size > 100) {
          const oldEntries = Array.from(this.cache.entries())
            .sort((a, b) => a[1].timestamp - b[1].timestamp)
            .slice(0, 20);
          oldEntries.forEach(([key]) => this.cache.delete(key));
        }
      }
      
      return result;
    } catch (error) {
      throw error;
    } finally {
      this.requestQueue.delete(cacheKey);
    }
  }

  async executeRequest(method, params) {
    const maxRetries = NODE_CONFIG.MAX_RETRIES;
    let attempt = 0;

    while (attempt < maxRetries) {
      attempt++;
      
      try {
        const requestBody = {
          jsonrpc: '2.0',
          method,
          params,
          id: this.requestId++
        };

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), NODE_CONFIG.TIMEOUT);

        const response = await fetch(this.nodeUrl, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify(requestBody),
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.status === 503) {
          if (NODE_CONFIG.NO_503_BACKOFF_METHODS.has(method)) {
            continue;
          }
          await sleep(NODE_CONFIG.RETRY_DELAY);
          continue;
        }

        const text = await response.text();

        if (response.status === 500) {
          if (text.includes('Scan already in progress')) {
            await sleep(NODE_CONFIG.RETRY_DELAY);
            continue;
          }
          throw new Error(`HTTP 500 after ${maxRetries} attempts: ${text}`);
        }

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${text}`);
        }

        let data;
        try {
          data = JSON.parse(text);
        } catch (parseError) {
          throw new Error(`Invalid JSON response: ${text.substring(0, 100)}`);
        }

        if (data.error) {
          if (data.error.code === -8 && method === 'gettxout') {
            return null;
          }
          throw new Error(`RPC Error: ${data.error.message} (Code: ${data.error.code})`);
        }

        if (data.id !== requestBody.id) {
          console.warn(`Response ID mismatch: expected ${requestBody.id}, got ${data.id}`);
        }

        return data.result;

      } catch (error) {
        const msg = String(error.message || error);
        
        if (msg.includes('503') || msg.includes('Scan already in progress') || msg.includes('code":-8')) {
          if (msg.includes('503') && NODE_CONFIG.NO_503_BACKOFF_METHODS.has(method)) {
            continue;
          }
          await sleep(NODE_CONFIG.RETRY_DELAY);
          continue;
        }

        if (msg.includes('aborted') || msg.includes('timeout')) {
          console.warn(`Network timeout for ${method}, attempt ${attempt}/${maxRetries}`);
          await sleep(NODE_CONFIG.RETRY_DELAY * attempt);
          if (attempt < maxRetries) continue;
        }

        if (attempt === maxRetries) {
          console.error(`RPC Error after ${maxRetries} attempts:`, method, params, error);
          eventBus.emit(EVENTS.SYSTEM_ERROR, { 
            type: 'rpc_error', 
            method, 
            error: error.message 
          });
          throw error;
        }
        
        await sleep(NODE_CONFIG.RETRY_DELAY * attempt);
      }
    }

    throw new Error(`RPC call failed after ${maxRetries} attempts: ${method}`);
  }

  shouldCache(method) {
    const cacheableMethods = new Set([
      'getblockchaininfo', 
      'getnetworkinfo', 
      'getmempoolinfo',
      'getrawtransaction'
    ]);
    return cacheableMethods.has(method);
  }

  getCacheDuration(method) {
    const durations = {
      'getblockchaininfo': 30000,
      'getnetworkinfo': 60000,
      'getmempoolinfo': 15000,
      'getrawtransaction': 300000
    };
    return durations[method] || 5000;
  }

  clearCache() {
    this.cache.clear();
    this.requestQueue.clear();
  }
}

// === ADDRESS MANAGEMENT ===
export class AddressManager {
  static getAddressType(address) {
    try {
      if (!address || typeof address !== 'string') return 'unknown';
      
      if (address.startsWith('nito1p')) return 'p2tr';
      if (address.startsWith('nito1')) return 'p2wpkh';
      if (address.startsWith('3')) return 'p2sh';
      if (address.startsWith('1')) return 'p2pkh';
      
      return 'unknown';
    } catch (error) {
      console.error('Error detecting address type:', error);
      return 'unknown';
    }
  }

  static detectScriptType(scriptPubKey) {
    try {
      if (!scriptPubKey || !VALIDATION_PATTERNS.SCRIPT_HEX.test(scriptPubKey)) {
        return 'unknown';
      }

      const script = Buffer.from(scriptPubKey, 'hex');
      
      if (script.length === 25 && 
          script[0] === 0x76 && script[1] === 0xa9 && script[2] === 0x14 && 
          script[23] === 0x88 && script[24] === 0xac) {
        return 'p2pkh';
      }
      
      if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
        return 'p2wpkh';
      }
      
      if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
        return 'p2sh';
      }
      
      if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
        return 'p2tr';
      }

      return 'unknown';
    } catch (error) {
      console.error('Error detecting script type:', error);
      return 'unknown';
    }
  }

  static async validateAddress(address) {
    try {
      const result = await rpcClient.call('validateaddress', [address]);
      return result && result.isvalid;
    } catch (error) {
      console.error('Error validating address:', error);
      return false;
    }
  }
}

// === TAPROOT UTILITIES ===
export class TaprootUtils {
  static toXOnly(pubkey) {
    if (!pubkey || pubkey.length < 33) {
      throw new Error(getTranslation('wallet.invalid_pubkey_conversion', 'Invalid public key for X-only conversion'));
    }
    return Buffer.from(pubkey.slice(1, 33));
  }

  static tapTweakHash(pubKey, h = Buffer.alloc(0)) {
    if (!window.bitcoin || !window.bitcoin.crypto) {
      throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library not available for tapTweakHash'));
    }
    return window.bitcoin.crypto.taggedHash(
      'TapTweak',
      Buffer.concat([TaprootUtils.toXOnly(pubKey), h])
    );
  }

  static tweakSigner(signer, opts = {}) {
    if (!window.ecc || typeof window.ecc.privateAdd !== 'function') {
      throw new Error(getTranslation('wallet.ecc_library_unavailable', 'ECC library not available for tweakSigner'));
    }

    let d = Uint8Array.from(signer.privateKey);
    const P = Uint8Array.from(signer.publicKey);

    if (P[0] === 3) {
      d = window.ecc.privateNegate(d);
    }

    const tweakHash = opts.tweakHash ? Buffer.from(opts.tweakHash) : Buffer.alloc(0);
    const tweak = Uint8Array.from(TaprootUtils.tapTweakHash(signer.publicKey, tweakHash));

    const dTweak = window.ecc.privateAdd(d, tweak);
    if (!dTweak) {
      throw new Error(getTranslation('wallet.invalid_tweaked_key', 'Invalid tweaked private key'));
    }

    const PTweak = window.ecc.pointFromScalar(dTweak, true);
    if (!PTweak) {
      throw new Error(getTranslation('transactions.failed_compute_tweaked_pubkey', 'Failed to compute tweaked public key'));
    }

    return {
      publicKey: PTweak,
      signSchnorr: (msg32) => {
        const auxRand = crypto.getRandomValues(new Uint8Array(32));
        return window.ecc.signSchnorr(msg32, dTweak, auxRand);
      }
    };
  }

  static async createTaprootAddress(publicKey, network) {
    if (!window.bitcoin || !window.bitcoin.payments) {
      throw new Error(getTranslation('wallet.bitcoin_library_unavailable', 'Bitcoin library not available'));
    }
    const internalPubkey = TaprootUtils.toXOnly(publicKey);
    const payment = window.bitcoin.payments.p2tr({ internalPubkey, network });
    return { address: payment.address, output: payment.output, internalPubkey };
  }

  static async prepareTaprootUtxo(utxo) {
    try {
      if (utxo && utxo.tapInternalKey && utxo.keyPair && utxo.scriptType === 'p2tr') {
        return utxo;
      }
      let kp = null;
      if (typeof window.getTaprootKeyPair === 'function') {
        kp = await window.getTaprootKeyPair();
      }
      if (!kp && window.hdManager && typeof window.hdManager.getTaprootKeyPair === 'function') {
        try { kp = await window.hdManager.getTaprootKeyPair(); } catch (_) {}
      }
      if (!kp || !kp.publicKey) {
        throw new Error(getTranslation('transactions.missing_taproot_keypair', 'Missing taproot keypair for UTXO preparation'));
      }
      const xonly = TaprootUtils.toXOnly(Buffer.from(kp.publicKey));
      const enriched = { ...utxo, keyPair: kp, tapInternalKey: xonly, scriptType: (utxo.scriptType || 'p2tr') };
      return enriched;
    } catch (e) {
      throw e;
    }
  }
}

// === EXPLORER UTILITIES ===
export async function getExplorerUrl(txid) {
  const primaryUrl = `https://explorer.nito.network/tx/${txid}`;
  const fallbackUrl = `https://nitoexplorer.org/tx/${txid}`;
  try {
    const res = await fetch('https://explorer.nito.network', { method: 'HEAD', mode: 'cors' });
    if (res.ok) return primaryUrl;
    return fallbackUrl;
  } catch (e) {
    return fallbackUrl;
  }
}

export async function checkTransactionConfirmation(txid) {
  const primaryApi = `https://explorer.nito.network/ext/gettx/${txid}`;
  const fallbackApi = `https://nitoexplorer.org/ext/gettx/${txid}`;
  try {
    const res = await fetch(primaryApi);
    if (res.ok) {
      const data = await res.json();
      return data.confirmations >= 1;
    }
    const fallbackRes = await fetch(fallbackApi);
    if (fallbackRes.ok) {
      const fallbackData = await fallbackRes.json();
      return fallbackData.confirmations >= 1;
    }
    return false;
  } catch (e) {
    return false;
  }
}

// === UTXO MATURITY VERIFICATION ===
async function checkUtxoMaturity(txid, vout) {
  try {
    const utxoInfo = await rpcClient.call('gettxout', [txid, vout, true]);
    if (!utxoInfo) return null;
    
    const confirmations = utxoInfo.confirmations || 0;
    const isCoinbase = utxoInfo.coinbase || false;
    
    if (isCoinbase && confirmations < 100) return null;
    if (!isCoinbase && confirmations < 1) return null;
    
    return {
      spendable: true,
      confirmations,
      coinbase: isCoinbase
    };
  } catch (error) {
    console.error(`UTXO maturity check failed for ${txid}:${vout}:`, error);
    return null;
  }
}

export async function filterMatureUtxos(utxoList) {
  if (!Array.isArray(utxoList) || !utxoList.length) return [];
  
  const BATCH_SIZE = 5;
  const matureUtxos = [];
  
  for (let i = 0; i < utxoList.length; i += BATCH_SIZE) {
    const batch = utxoList.slice(i, i + BATCH_SIZE);
    
    const results = await Promise.allSettled(
      batch.map(async (utxo) => {
        const maturityInfo = await checkUtxoMaturity(utxo.txid, utxo.vout);
        return maturityInfo ? utxo : null;
      })
    );
    
    results.forEach(result => {
      if (result.status === 'fulfilled' && result.value) {
        matureUtxos.push(result.value);
      }
    });
    
    if (i + BATCH_SIZE < utxoList.length) {
      await sleep(50);
    }
  }
  
  return matureUtxos;
}

// === HD WALLET UTXO SCANNER ===
export class HDUTXOScanner {
  constructor(rpcClient) {
    this.rpc = rpcClient;
    this.cache = new Map();
  }

  async scanHDUTXOsWithDescriptors(hdWallet, addressFamily) {
    try {
      const descriptor = this.createDescriptor(hdWallet, addressFamily);
      const scan = await this.rpc.call('scantxoutset', [
        'start', 
        [{ desc: descriptor, range: HD_CONFIG.START_RANGE }]
      ]);
      
      if (!scan || !scan.success || !scan.unspents) return [];
      
      return this.enrichUTXOs(scan.unspents, hdWallet, addressFamily);
    } catch (error) {
      console.warn(`Descriptor scan failed for ${addressFamily}, falling back to legacy scan:`, error);
      return this.scanHDUTXOsLegacy(hdWallet, addressFamily);
    }
  }

  createDescriptor(hdWallet, family) {
    if (!hdWallet || !hdWallet.derivePath) {
      throw new Error('Invalid HD wallet provided');
    }

    const derivationPath = HD_CONFIG.DERIVATION_PATHS[family];
    if (!derivationPath) {
      throw new Error(`Unknown family: ${family}`);
    }

    try {
      const account = hdWallet.derivePath(derivationPath);
      const xpub = account.neutered().toBase58();
      
      const prefixes = {
        'legacy': 'pkh',
        'p2sh': 'sh(wpkh',
        'bech32': 'wpkh',
        'taproot': 'tr'
      };
      
      const prefix = prefixes[family];
      if (!prefix) throw new Error(`Unknown family: ${family}`);
      
      if (family === 'p2sh') {
        return `${prefix}(${xpub}/0/*))`;
      }
      return `${prefix}(${xpub}/0/*)`;
    } catch (error) {
      console.error(`Descriptor creation failed for ${family}:`, error);
      throw error;
    }
  }

  enrichUTXOs(unspents, hdWallet, family) {
    return unspents.map(utxo => {
      const scriptType = AddressManager.detectScriptType(utxo.scriptPubKey);
      
      return {
        txid: utxo.txid,
        vout: utxo.vout,
        amount: utxo.amount,
        scriptPubKey: utxo.scriptPubKey,
        scriptType,
        family,
        desc: utxo.desc
      };
    });
  }

  async scanHDUTXOsLegacy(hdWallet, family) {
    const utxos = [];
    const seen = new Set();
    
    for (let chunk = 0; chunk < HD_CONFIG.SCAN_MAX_CHUNKS; chunk++) {
      const start = chunk * HD_CONFIG.SCAN_CHUNK;
      const { descriptors } = this.deriveAddressChunk(hdWallet, family, start, HD_CONFIG.SCAN_CHUNK);
      
      if (!descriptors.length) break;
      
      try {
        const scan = await this.rpc.call('scantxoutset', ['start', descriptors]);
        const unspents = (scan && scan.unspents) ? scan.unspents : [];
        
        if (!unspents.length && chunk > 0) break;
        
        for (const utxo of unspents) {
          const key = `${utxo.txid}:${utxo.vout}`;
          if (seen.has(key)) continue;
          seen.add(key);
          
          utxos.push({
            txid: utxo.txid,
            vout: utxo.vout,
            amount: utxo.amount,
            scriptPubKey: utxo.scriptPubKey,
            scriptType: AddressManager.detectScriptType(utxo.scriptPubKey),
            family
          });
        }
      } catch (error) {
        console.error(`Legacy HD scan failed for chunk ${chunk}:`, error);
        break;
      }
    }
    
    return utxos;
  }

  deriveAddressChunk(hdWallet, family, start, count) {
    if (!hdWallet || !HD_CONFIG.DERIVATION_PATHS[family]) {
      return { descriptors: [] };
    }

    const descriptors = [];
    
    try {
      const account = hdWallet.derivePath(HD_CONFIG.DERIVATION_PATHS[family]);
      
      for (let chain = 0; chain <= 1; chain++) {
        const branch = account.derive(chain);
        
        for (let i = start; i < start + count; i++) {
          const node = branch.derive(i);
          
          if (!window.bitcoin || !window.ECPair) {
            console.warn('Bitcoin libraries not available for address derivation');
            continue;
          }

          const keyPair = window.ECPair.fromPrivateKey(node.privateKey);
          const address = this.deriveAddressForFamily(keyPair, family);
          
          if (address) {
            descriptors.push(`addr(${address})`);
          }
        }
      }
    } catch (error) {
      console.error(`Address derivation failed for ${family}:`, error);
    }
    
    return { descriptors };
  }

  deriveAddressForFamily(keyPair, family) {
    if (!window.bitcoin || !keyPair) return null;

    const pubkey = Buffer.from(keyPair.publicKey);
    const network = NITO_NETWORK;
    
    try {
      switch (family) {
        case 'legacy':
          return window.bitcoin.payments.p2pkh({ pubkey, network }).address;
          
        case 'p2sh':
          const p2wpkh = window.bitcoin.payments.p2wpkh({ pubkey, network });
          return window.bitcoin.payments.p2sh({ redeem: p2wpkh, network }).address;
          
        case 'bech32':
          return window.bitcoin.payments.p2wpkh({ pubkey, network }).address;
          
        case 'taproot':
          const internalKey = pubkey.slice(1, 33);
          return window.bitcoin.payments.p2tr({ internalPubkey: internalKey, network }).address;
          
        default:
          return null;
      }
    } catch (error) {
      console.error(`Address derivation failed for ${family}:`, error);
      return null;
    }
  }

  async scanAllFamilies(hdWallet) {
    const families = ['bech32', 'taproot', 'p2sh', 'legacy'];
    const allUtxos = [];
    const seen = new Set();
    
    for (const family of families) {
      try {
        const familyUtxos = await this.scanHDUTXOsWithDescriptors(hdWallet, family);
        
        for (const utxo of familyUtxos) {
          const key = `${utxo.txid}:${utxo.vout}`;
          if (!seen.has(key)) {
            seen.add(key);
            allUtxos.push(utxo);
          }
        }
      } catch (error) {
        console.warn(`Failed to scan ${family} UTXOs:`, error);
      }
    }
    
    return allUtxos;
  }

  async scanSpecificFamily(hdWallet, family) {
    try {
      const familyUtxos = await this.scanHDUTXOsWithDescriptors(hdWallet, family);
      return familyUtxos;
    } catch (error) {
      console.error(`Failed to scan ${family} UTXOs:`, error);
      return [];
    }
  }
}

// === MAIN UTXO AND BALANCE FUNCTIONS ===
export async function utxos(address, isHD = false, hdWallet = null) {
  try {
    const cacheKey = `utxos:${address}:${isHD}`;
    
    const cachedData = SMART_UTXO_CACHE.get(cacheKey);
    if (cachedData) {
      console.log(`[UTXO-CACHE] Cache hit for ${address.substring(0, 10)}...`);
      return cachedData;
    }

    console.log(`[UTXO-CACHE] Cache miss, scanning blockchain for ${address.substring(0, 10)}...`);

    let result;

    if (isHD && hdWallet) {
      const scanner = new HDUTXOScanner(rpcClient);
      const addressType = AddressManager.getAddressType(address);
      
      if (addressType === 'p2wpkh') {
        const allUtxos = await scanner.scanAllFamilies(hdWallet);
        const cumulativeUtxos = allUtxos.filter(utxo => 
          ['p2wpkh', 'p2pkh', 'p2sh'].includes(utxo.scriptType)
        );
        result = await filterMatureUtxos(cumulativeUtxos);
      } else if (addressType === 'p2tr') {
        const taprootUtxos = await scanner.scanSpecificFamily(hdWallet, 'taproot');
        result = await filterMatureUtxos(taprootUtxos);
      } else {
        let familyMap = {
          'p2sh': 'p2sh',
          'p2pkh': 'legacy'
        };
        
        const family = familyMap[addressType];
        if (family) {
          const hdUtxos = await scanner.scanSpecificFamily(hdWallet, family);
          result = await filterMatureUtxos(hdUtxos);
        } else {
          console.warn(`[UTXO] Unknown address type: ${addressType}`);
          result = [];
        }
      }
    } else {
      const scan = await rpcClient.call('scantxoutset', ['start', [`addr(${address})`]]);
      if (!scan || !scan.success || !scan.unspents) {
        result = [];
      } else {
        const validUtxos = scan.unspents.map(utxo => {
          if (!VALIDATION_PATTERNS.SCRIPT_HEX.test(utxo.scriptPubKey)) {
            throw new Error(`Invalid scriptPubKey for UTXO ${utxo.txid}:${utxo.vout}`);
          }
          
          const scriptType = AddressManager.detectScriptType(utxo.scriptPubKey);
          if (scriptType === 'unknown') {
            console.warn(`Unknown script type for UTXO ${utxo.txid}:${utxo.vout}`);
          }
          
          return {
            txid: utxo.txid,
            vout: utxo.vout,
            amount: utxo.amount,
            scriptPubKey: utxo.scriptPubKey,
            scriptType
          };
        });
        
        result = await filterMatureUtxos(validUtxos);
      }
    }

    SMART_UTXO_CACHE.set(cacheKey, result);

    eventBus.emit(EVENTS.UTXO_UPDATED, { address, count: result.length });
    
    return result;
    
  } catch (error) {
    console.error('[UTXO] Fetch error:', error);
    throw new Error(`Failed to fetch UTXOs: ${error.message}`);
  }
}

export async function balance(address, isHD = false, hdWallet = null) {
  try {
    const cacheKey = `balance:${address}:${isHD}`;
    
    const cachedBalance = SMART_BALANCE_CACHE.get(cacheKey);
    if (cachedBalance !== null) {
      console.log(`[BALANCE-CACHE] Cache hit for ${address.substring(0, 10)}...`);
      return cachedBalance;
    }

    console.log(`[BALANCE-CACHE] Cache miss, calculating for ${address.substring(0, 10)}...`);

    let result;

    if (isHD && hdWallet) {
      const addressType = AddressManager.getAddressType(address);
      
      if (addressType === 'p2wpkh') {
        const utxoList = await utxos(address, true, hdWallet);
        result = utxoList.reduce((sum, utxo) => sum + (utxo.amount || 0), 0);
      } else {
        const utxoList = await utxos(address, true, hdWallet);
        result = utxoList.reduce((sum, utxo) => sum + (utxo.amount || 0), 0);
      }
    } else {
      const scan = await rpcClient.call('scantxoutset', ['start', [`addr(${address})`]]);
      result = (scan && scan.total_amount) || 0;
    }

    SMART_BALANCE_CACHE.set(cacheKey, result);

    eventBus.emit(EVENTS.WALLET_BALANCE_UPDATED, { address, balance: result });

    return result;
  } catch (error) {
    console.error('[BALANCE] Fetch error:', error);
    throw new Error(`Failed to fetch balance: ${error.message}`);
  }
}

// === RAW TRANSACTION HANDLING ===
export async function fetchRawTxHex(txid) {
  if (!VALIDATION_PATTERNS.TXID.test(txid)) {
    throw new Error('Invalid transaction ID format');
  }

  if (RAW_TX_CACHE.has(txid)) {
    return RAW_TX_CACHE.get(txid);
  }
  
  try {
    const rawTx = await rpcClient.call('getrawtransaction', [txid, true]);
    const hex = rawTx && rawTx.hex;
    
    if (!hex) {
      throw new Error(`Raw transaction hex not found for ${txid}`);
    }
    
    RAW_TX_CACHE.set(txid, hex);
    
    if (RAW_TX_CACHE.size > 100) {
      const keys = Array.from(RAW_TX_CACHE.keys());
      for (let i = 0; i < 20; i++) {
        RAW_TX_CACHE.delete(keys[i]);
      }
    }
    
    return hex;
  } catch (error) {
    console.error(`Failed to fetch raw tx ${txid}:`, error);
    throw error;
  }
}

// === UTXO FILTERING ===
export async function filterOpReturnUtxos(utxos) {
  if (!Array.isArray(utxos)) return [];

  const filteredUtxos = utxos.filter(utxo => 
    utxo && 
    typeof utxo.amount === 'number' && 
    utxo.amount >= TRANSACTION_CONFIG.MIN_CONSOLIDATION_FEE
  );
  
  return filteredUtxos;
}

// === CACHE MANAGEMENT ===
export function clearBlockchainCaches() {
  console.log('[CACHE] Clearing ALL blockchain caches including UTXOs');
  
  SMART_UTXO_CACHE.clear(false);
  SMART_BALANCE_CACHE.clear(false);
  SMART_TX_CACHE.clear(false);
  
  RAW_TX_CACHE.clear();
  UTXO_CACHE.clear();
  BALANCE_CACHE.clear();
  
  rpcClient.clearCache();
  
  console.log('[CACHE] All caches cleared successfully');
}

export function invalidateUTXOCache(address, isHD = false) {
  const cacheKey = `utxos:${address}:${isHD}`;
  SMART_UTXO_CACHE.invalidate(cacheKey);
  console.log(`[CACHE] Invalidated UTXO cache for ${address.substring(0, 10)}...`);
}

export async function refreshUTXOCache(address, isHD = false, hdWallet = null) {
  invalidateUTXOCache(address, isHD);
  return await utxos(address, isHD, hdWallet);
}

// === GLOBAL RPC CLIENT INSTANCE ===
export const rpcClient = new SecureRPCClient();

// === GLOBAL RPC FUNCTION ===
export async function rpc(method, params = []) {
  return rpcClient.call(method, params);
}

// === EVENT LISTENERS ===
eventBus.on(EVENTS.WALLET_INFO_REQUEST, async () => {
  try {
    const walletInfo = await requestWalletInfo();
    eventBus.emit(EVENTS.WALLET_INFO_RESPONSE, walletInfo);
  } catch (error) {
    eventBus.emit(EVENTS.WALLET_INFO_RESPONSE, { address: '', isReady: false });
  }
});

// === GLOBAL COMPATIBILITY ===
if (typeof window !== 'undefined') {
  window.rpc = rpc;
  window.utxos = utxos;
  window.balance = balance;
  window.fetchRawTxHex = fetchRawTxHex;
  window.filterOpReturnUtxos = filterOpReturnUtxos;
  window.filterMatureUtxos = filterMatureUtxos;
  window.clearBlockchainCaches = clearBlockchainCaches;
  window.invalidateUTXOCache = invalidateUTXOCache;
  window.refreshUTXOCache = refreshUTXOCache;
  window.TaprootUtils = TaprootUtils;
  window.AddressManager = AddressManager;
  window.getExplorerUrl = getExplorerUrl;
  window.checkTransactionConfirmation = checkTransactionConfirmation;
  window.handleError500WithRetry = handleError500WithRetry;
}