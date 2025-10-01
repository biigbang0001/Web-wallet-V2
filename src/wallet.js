// Wallet Management for NITO Wallet

import { NITO_NETWORK, HD_CONFIG, SECURITY_CONFIG, ELEMENT_IDS, FEATURE_FLAGS, getTranslation } from './config.js';
import { keyManager, validateInput, deriveFromCredentials, armInactivityTimerSafely, updateInactivityTimer } from './security.js';
import { eventBus, EVENTS } from './events.js';
import { getBitcoinLibraries, waitForLibraries } from './vendor.js';
import { TaprootUtils, AddressManager } from './blockchain.js';
import { showBalanceLoadingSpinner } from './ui-popups.js';

// === GLOBAL STATE ===
let lastTxid = null;
window._lastConsolidationTxid = null;

// === HD WALLET MANAGER ===
export class HDWalletManager {
  constructor() {
    this.hdWallet = null;
    this.currentMnemonic = null;
  }

  async generateMnemonic(wordCount = 24) {
    try {
      const { bip39 } = await getBitcoinLibraries();
      
      const entropyBits = wordCount === 24 ? 256 : 128;
      const entropyBytes = entropyBits / 8;
      const entropy = crypto.getRandomValues(new Uint8Array(entropyBytes));
      const entropyHex = Array.from(entropy).map(x => x.toString(16).padStart(2, '0')).join('');
      
      return bip39.entropyToMnemonic(entropyHex);
    } catch (error) {
      const msg = getTranslation('wallet.mnemonic_generation_failed', 'Failed to generate mnemonic phrase');
      throw new Error(msg);
    }
  }

  async importHDWallet(seedOrXprv, passphrase = '') {
    if (window.isOperationActive && window.isOperationActive('wallet-import')) {
      const msg = getTranslation('wallet.import_in_progress', 'Wallet import already in progress');
      throw new Error(msg);
    }
    
    if (window.startOperation) window.startOperation('wallet-import');
    
    try {
      const { bitcoin, bip32, bip39 } = await getBitcoinLibraries();
      let seed;
      
      if (seedOrXprv.startsWith('xprv')) {
        this.hdWallet = bip32.fromBase58(seedOrXprv, NITO_NETWORK);
        this.currentMnemonic = null;
      } else {
        const mnemonic = seedOrXprv.trim();
        if (!bip39.validateMnemonic(mnemonic)) {
          const msg = getTranslation('wallet.invalid_mnemonic', 'Invalid mnemonic phrase');
          throw new Error(msg);
        }
        
        seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
        this.hdWallet = bip32.fromSeed(seed, NITO_NETWORK);
        this.currentMnemonic = mnemonic;
      }

      const addresses = this.deriveMainAddresses();
      
      await keyManager.storeKey('hdWallet', {
        masterKey: this.hdWallet.toBase58(),
        mnemonic: this.currentMnemonic
      });
      
      await keyManager.storeKey('bech32KeyPair', {
        privateKey: addresses.keyPair.privateKey.toString('hex'),
        publicKey: addresses.publicKey.toString('hex')
      });
      
      if (addresses.taprootKeyPair) {
        await keyManager.storeKey('taprootKeyPair', {
          privateKey: addresses.taprootKeyPair.privateKey.toString('hex'),
          publicKey: addresses.taprootPublicKey.toString('hex')
        });
      }

      return addresses;
    } catch (error) {
      const msg = getTranslation('wallet.hd_import_failed', 'HD wallet import failed: {{error}}', { error: error.message });
      throw new Error(msg);
    } finally {
      if (window.endOperation) window.endOperation('wallet-import');
    }
  }

  deriveMainAddresses() {
    if (!this.hdWallet) {
      const msg = getTranslation('wallet.hd_wallet_not_initialized', 'HD wallet not initialized');
      throw new Error(msg);
    }

    try {
      const { bitcoin, ECPair } = window;
      if (!bitcoin || !ECPair) {
        const msg = getTranslation('wallet.bitcoin_libraries_unavailable', 'Bitcoin libraries not available');
        throw new Error(msg);
      }

      const bech32Node = this.hdWallet.derivePath(HD_CONFIG.DERIVATION_PATHS.bech32 + "/0/0");
      const legacyNode = this.hdWallet.derivePath(HD_CONFIG.DERIVATION_PATHS.legacy + "/0/0");
      const p2shNode = this.hdWallet.derivePath(HD_CONFIG.DERIVATION_PATHS.p2sh + "/0/0");
      const taprootNode = this.hdWallet.derivePath(HD_CONFIG.DERIVATION_PATHS.taproot + "/0/0");

      const pubkey = Buffer.from(bech32Node.publicKey);
      const keyPair = ECPair.fromPrivateKey(bech32Node.privateKey, { network: NITO_NETWORK });

      const p2pkh = bitcoin.payments.p2pkh({ 
        pubkey: Buffer.from(legacyNode.publicKey), 
        network: NITO_NETWORK 
      });
      
      const p2wpkh = bitcoin.payments.p2wpkh({ 
        pubkey: pubkey, 
        network: NITO_NETWORK 
      });
      
      const p2sh = bitcoin.payments.p2sh({
        redeem: bitcoin.payments.p2wpkh({ 
          pubkey: Buffer.from(p2shNode.publicKey), 
          network: NITO_NETWORK 
        }),
        network: NITO_NETWORK
      });

      const tapInternalPubkey = TaprootUtils.toXOnly(taprootNode.publicKey);
      const p2tr = bitcoin.payments.p2tr({ 
        internalPubkey: tapInternalPubkey, 
        network: NITO_NETWORK 
      });
      const taprootKeyPair = ECPair.fromPrivateKey(taprootNode.privateKey, { network: NITO_NETWORK });

      const result = {
        legacy: p2pkh.address,
        p2sh: p2sh.address,
        bech32: p2wpkh.address,
        taproot: p2tr.address,
        keyPair: keyPair,
        publicKey: pubkey,
        taprootKeyPair: taprootKeyPair,
        taprootPublicKey: tapInternalPubkey,
        hdMasterKey: this.hdWallet.toBase58(),
        mnemonic: this.currentMnemonic
      };

      if (!result.taproot || !result.taproot.startsWith('nito1p')) {
        console.warn('[WALLET] Invalid Taproot address generated:', result.taproot);
      }

      return result;
    } catch (error) {
      const msg = getTranslation('wallet.address_derivation_failed', 'Failed to derive addresses: {{error}}', { error: error.message });
      throw new Error(msg);
    }
  }

  getHdAccountNode(family) {
    if (!this.hdWallet) {
      const msg = getTranslation('wallet.hd_wallet_not_initialized', 'HD wallet not initialized');
      throw new Error(msg);
    }
    
    const path = HD_CONFIG.DERIVATION_PATHS[family];
    if (!path) {
      const msg = getTranslation('wallet.unknown_address_family', 'Unknown address family: {{family}}', { family });
      throw new Error(msg);
    }
    
    return this.hdWallet.derivePath(path);
  }

  deriveKeyFor(family, branch, index) {
    if (!window.bitcoin || !window.ECPair) {
      const msg = getTranslation('wallet.bitcoin_libraries_unavailable', 'Bitcoin libraries not available');
      throw new Error(msg);
    }

    const account = this.getHdAccountNode(family);
    const node = account.derive(branch).derive(index);
    const keyPair = window.ECPair.fromPrivateKey(node.privateKey, { network: NITO_NETWORK });
    const pub = Buffer.from(node.publicKey);
    
    if (family === 'taproot') {
      return { 
        keyPair, 
        tapInternalKey: TaprootUtils.toXOnly(pub), 
        scriptType: 'p2tr' 
      };
    }
    
    if (family === 'legacy') {
      return { keyPair, scriptType: 'p2pkh' };
    }
    
    if (family === 'p2sh') {
      const p2w = window.bitcoin.payments.p2wpkh({ pubkey: pub, network: NITO_NETWORK });
      return { 
        keyPair, 
        redeemScript: p2w.output, 
        scriptType: 'p2sh' 
      };
    }
    
    return { keyPair, scriptType: 'p2wpkh' };
  }

  async scanHdUtxosForFamily(family) {
    const allUtxos = [];
    const seen = new Set();

    for (let chunk = 0; chunk < 40; chunk++) {
      const start = chunk * 50;
      const { descriptors, byScriptHex } = this.deriveHdChunk(family, start, 50);
      if (!descriptors.length) break;

      let scan;
      try {
        scan = await window.rpc('scantxoutset', ['start', descriptors]);
      } catch (e) {
        console.warn(`[HD-SCAN] Error scanning chunk ${chunk} for ${family}:`, e);
        break;
      }
      
      const unspents = (scan && scan.unspents) ? scan.unspents : [];
      if (!unspents.length && chunk > 0) break;

      for (const u of unspents) {
        if (!/^[0-9a-fA-F]+$/.test(u.scriptPubKey)) continue;
        const scriptHex = u.scriptPubKey.toLowerCase();
        const keyInfo = byScriptHex[scriptHex];
        const key = `${u.txid}:${u.vout}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const scriptType = AddressManager.detectScriptType(u.scriptPubKey);
        const enriched = {
          txid: u.txid,
          vout: u.vout,
          amount: u.amount,
          scriptPubKey: u.scriptPubKey,
          scriptType
        };
        
        if (keyInfo) {
          enriched.keyPair = keyInfo.keyPair;
          if (keyInfo.tapInternalKey) enriched.tapInternalKey = keyInfo.tapInternalKey;
          if (keyInfo.redeemScript) enriched.redeemScript = keyInfo.redeemScript;
        }
        allUtxos.push(enriched);
      }
    }

    return allUtxos;
  }

  deriveHdChunk(family, start, count) {
    const byScriptHex = {};
    const descriptors = [];
    const network = NITO_NETWORK;
    const { bitcoin, ECPair } = window;

    if (family === 'bech32') {
      const account = this.hdWallet.derivePath("m/84'/0'/0'");
      for (let chain = 0; chain <= 1; chain++) {
        const branch = account.derive(chain);
        for (let i = start; i < start + count; i++) {
          const node = branch.derive(i);
          if (!node.privateKey) continue;
          const pubkey = Buffer.from(node.publicKey);
          const keyPair = ECPair.fromPrivateKey(node.privateKey, { network });
          const pay = bitcoin.payments.p2wpkh({ pubkey, network });
          if (!pay.address || !pay.output) continue;
          const scriptHex = pay.output.toString('hex').toLowerCase();
          byScriptHex[scriptHex] = { keyPair, scriptType: 'p2wpkh' };
          descriptors.push(`addr(${pay.address})`);
        }
      }
    } else if (family === 'taproot') {
      const account = this.hdWallet.derivePath("m/86'/0'/0'");
      for (let chain = 0; chain <= 1; chain++) {
        const branch = account.derive(chain);
        for (let i = start; i < start + count; i++) {
          const node = branch.derive(i);
          if (!node.privateKey) continue;
          const internal = TaprootUtils.toXOnly(node.publicKey);
          const keyPair = ECPair.fromPrivateKey(node.privateKey, { network });
          const pay = bitcoin.payments.p2tr({ internalPubkey: internal, network });
          if (!pay.address || !pay.output) continue;
          const scriptHex = pay.output.toString('hex').toLowerCase();
          byScriptHex[scriptHex] = { keyPair, scriptType: 'p2tr', tapInternalKey: internal };
          descriptors.push(`addr(${pay.address})`);
        }
      }
    } else if (family === 'legacy') {
      const account = this.getHdAccountNode(family);
      for (let chain = 0; chain <= 1; chain++) {
        const branch = account.derive(chain);
        for (let i = start; i < start + count; i++) {
          const node = branch.derive(i);
          if (!node.privateKey) continue;
          const pubkey = Buffer.from(node.publicKey);
          const keyPair = ECPair.fromPrivateKey(node.privateKey, { network });
          const pay = bitcoin.payments.p2pkh({ pubkey, network });
          if (!pay.address || !pay.output) continue;
          byScriptHex[pay.output.toString('hex').toLowerCase()] = { keyPair, scriptType: 'p2pkh' };
          descriptors.push(`addr(${pay.address})`);
        }
      }
    } else if (family === 'p2sh') {
      const account = this.getHdAccountNode(family);
      for (let chain = 0; chain <= 1; chain++) {
        const branch = account.derive(chain);
        for (let i = start; i < start + count; i++) {
          const node = branch.derive(i);
          if (!node.privateKey) continue;
          const pubkey = Buffer.from(node.publicKey);
          const keyPair = ECPair.fromPrivateKey(node.privateKey, { network });
          const p2w = bitcoin.payments.p2wpkh({ pubkey, network });
          const p2s = bitcoin.payments.p2sh({ redeem: p2w, network });
          if (!p2s.address || !p2s.output) continue;
          byScriptHex[p2s.output.toString('hex').toLowerCase()] = { keyPair, scriptType: 'p2sh', redeemScript: p2w.output };
          descriptors.push(`addr(${p2s.address})`);
        }
      }
    }

    return { descriptors, byScriptHex };
  }

  async utxosAllForBech32() {
    const families = ['bech32', 'p2sh', 'legacy'];
    const parts = [];
    
    for (const fam of families) {
      try { 
        const familyUtxos = await this.scanHdUtxosForFamily(fam); 
        parts.push(familyUtxos);
      } catch (e) {
        console.warn(`[HD-UTXO] Failed to scan ${fam}:`, e);
        parts.push([]);
      }
    }
    
    const seen = new Set();
    const merged = [];
    for (const arr of parts) {
      for (const u of arr) {
        const k = `${u.txid}:${u.vout}`;
        if (seen.has(k)) continue; 
        seen.add(k);
        merged.push(u);
      }
    }
    
    return merged;
  }

  async utxosForTaproot() {
    return await this.scanHdUtxosForFamily('taproot');
  }
}

// === WALLET STATE MANAGEMENT ===
class WalletState {
  constructor() {
    this.reset();
    this.setupEventListeners();
  }

  reset() {
    this.walletAddress = '';
    this.legacyAddress = '';
    this.p2shAddress = '';
    this.bech32Address = '';
    this.taprootAddress = '';
    this.importType = '';
    this.lastActionTime = null;
    this.inactivityTimeout = null;
    this.timerInterval = null;
    this.consolidateButtonInjected = false;
    this.totalBalance = 0;
    this._refreshBlocked = false;
    this._pendingConfirmations = new Set();
  }

  setupEventListeners() {
    eventBus.on(EVENTS.WALLET_INFO_REQUEST, () => {
      eventBus.emit(EVENTS.WALLET_INFO_RESPONSE, {
        address: this.bech32Address,
        isReady: this.isReady(),
        addresses: {
          bech32: this.bech32Address,
          legacy: this.legacyAddress,
          p2sh: this.p2shAddress,
          taproot: this.taprootAddress
        }
      });
    });

    eventBus.on(EVENTS.TIMER_ARM_REQUEST, () => {
      this.updateLastActionTime();
    });
  }

  updateLastActionTime() {
    this.lastActionTime = Date.now();
    
    if (this.inactivityTimeout) {
      clearTimeout(this.inactivityTimeout);
      this.inactivityTimeout = null;
    }
    
    this.inactivityTimeout = setTimeout(() => {
      this.clearSensitiveData();
    }, SECURITY_CONFIG.INACTIVITY_TIMEOUT);
  }

  clearSensitiveData() {
    const elements = [
      ELEMENT_IDS.HD_MASTER_KEY,
      ELEMENT_IDS.MNEMONIC_PHRASE,
      ELEMENT_IDS.GENERATED_ADDRESS,
      'privateKey',
      'privateKeyHex'
    ];

    elements.forEach(id => {
      const element = document.getElementById(id);
      if (element) {
        element.textContent = '';
        element.classList.add('blurred');
      }
    });

    eventBus.emit(EVENTS.INACTIVITY_WARNING);
  }

  isReady() {
    return keyManager.hasKey('bech32KeyPair') && this.bech32Address;
  }

  async getWalletKeyPair() {
    try {
      const keyData = await keyManager.getKey('bech32KeyPair');
      if (!keyData) return null;
      
      const { ECPair } = await getBitcoinLibraries();
      return ECPair.fromPrivateKey(Buffer.from(keyData.privateKey, 'hex'), { network: NITO_NETWORK });
    } catch (error) {
      return null;
    }
  }

  async getWalletPublicKey() {
    try {
      const keyData = await keyManager.getKey('bech32KeyPair');
      if (!keyData) return null;
      return Buffer.from(keyData.publicKey, 'hex');
    } catch (error) {
      return null;
    }
  }

  async getTaprootKeyPair() {
    try {
      const keyData = await keyManager.getKey('taprootKeyPair');
      if (!keyData) return null;
      
      const { ECPair } = await getBitcoinLibraries();
      return ECPair.fromPrivateKey(Buffer.from(keyData.privateKey, 'hex'), { network: NITO_NETWORK });
    } catch (error) {
      return null;
    }
  }

  async getTaprootPublicKey() {
    try {
      const keyData = await keyManager.getKey('taprootKeyPair');
      if (!keyData) return null;
      return Buffer.from(keyData.publicKey, 'hex');
    } catch (error) {
      return null;
    }
  }

  async updateBalance() {
    if (window.isOperationActive && window.isOperationActive('balance-update')) {
      return this.totalBalance;
    }
    
    if (window.startOperation) window.startOperation('balance-update');
    
    try {
      let total = 0;
      
      if (window.balance) {
        if (this.bech32Address) {
          const bech32Balance = await window.balance(this.bech32Address, this.importType === 'hd', this.importType === 'hd' ? hdManager.hdWallet : null);
          total += bech32Balance || 0;
        }
        
        if (this.taprootAddress && this.importType === 'hd') {
          const taprootBalance = await window.balance(this.taprootAddress, true, hdManager.hdWallet);
          total += taprootBalance || 0;
        }
      }
      
      this.totalBalance = total;
      return total;
    } catch (error) {
      return this.totalBalance;
    } finally {
      if (window.endOperation) window.endOperation('balance-update');
    }
  }
}

// === ADDRESS IMPORTS ===
export async function importWIF(wif) {
  try {
    if (!validateInput(wif, 'wif')) {
      const msg = getTranslation('wallet.invalid_wif_format', 'Invalid WIF format');
      throw new Error(msg);
    }

    const { bitcoin, ECPair } = await getBitcoinLibraries();

    let kp = ECPair.fromWIF(wif, NITO_NETWORK);
    
    if (!kp.publicKey || kp.publicKey.length !== 33) {
      if (!kp.privateKey) {
        const msg = getTranslation('wallet.wif_without_private_key', 'WIF without private key');
        throw new Error(msg);
      }
      kp = ECPair.fromPrivateKey(Buffer.from(kp.privateKey), { 
        network: NITO_NETWORK, 
        compressed: true 
      });
    }
    
    const pubkeyBuffer = Buffer.from(kp.publicKey);
    
    const p2pkh = bitcoin.payments.p2pkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
    const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh, network: NITO_NETWORK });
    
    return {
      legacy: p2pkh.address,
      p2sh: p2sh.address,
      bech32: p2wpkh.address,
      taproot: '',
      keyPair: kp,
      publicKey: pubkeyBuffer
    };
  } catch (error) {
    const msg = getTranslation('wallet.invalid_wif_error', 'Invalid WIF: {{error}}', { error: error.message });
    throw new Error(msg);
  }
}

export async function importHex(hex) {
  try {
    if (!validateInput(hex, 'hex')) {
      const msg = getTranslation('wallet.invalid_hex_format', 'Invalid hex format - must be 64 characters');
      throw new Error(msg);
    }

    const { bitcoin, ECPair } = await getBitcoinLibraries();

    const privateKeyBuffer = Buffer.from(hex, 'hex');
    if (privateKeyBuffer.length !== 32) {
      const msg = getTranslation('wallet.private_key_32_bytes', 'Private key must be 32 bytes');
      throw new Error(msg);
    }
    
    const kp = ECPair.fromPrivateKey(privateKeyBuffer, { network: NITO_NETWORK });
    const pubkeyBuffer = Buffer.from(kp.publicKey);
    
    const p2pkh = bitcoin.payments.p2pkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
    const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh, network: NITO_NETWORK });
    
    return {
      legacy: p2pkh.address,
      p2sh: p2sh.address,
      bech32: p2wpkh.address,
      taproot: '',
      keyPair: kp,
      publicKey: pubkeyBuffer
    };
  } catch (error) {
    const msg = getTranslation('wallet.invalid_private_key_error', 'Invalid private key: {{error}}', { error: error.message });
    throw new Error(msg);
  }
}

// === UNIFIED IMPORT FUNCTION ===
export async function importWallet(arg1, arg2) {
  try {
    if (typeof arg2 === 'string' && typeof arg1 === 'string') {
      const email = arg1.trim().toLowerCase();
      const password = arg2.trim();
      
      if (!email || !password) {
        const msg = getTranslation('wallet.missing_email_password', 'Missing email or password');
        throw new Error(msg);
      }
      
      if (!validateInput(email, 'email')) {
        const msg = getTranslation('wallet.invalid_email_format', 'Invalid email format');
        throw new Error(msg);
      }
      
      const mnemonic = await deriveFromCredentials(email, password, 24);
      const addresses = await hdManager.importHDWallet(mnemonic);
      
      walletState.legacyAddress = addresses.legacy;
      walletState.p2shAddress = addresses.p2sh;
      walletState.bech32Address = addresses.bech32;
      walletState.taprootAddress = addresses.taproot;
      walletState.walletAddress = addresses.bech32;
      walletState.importType = 'hd';
      
      syncGlobalState();
      eventBus.emit(EVENTS.WALLET_IMPORTED, { addresses, importType: 'email' });
      
      if (FEATURE_FLAGS.LOG_ADDRESSES) {
        console.log('=== WALLET ADDRESSES (HD) ===');
        console.log('Legacy (P2PKH)  :', addresses.legacy);
        console.log('P2SH (Wrapped)  :', addresses.p2sh);
        console.log('Bech32 (Native) :', addresses.bech32);
        console.log('Bech32m (Taproot):', addresses.taproot);
        console.log('============================');
      }
      
      console.log('[WALLET] Email wallet connected successfully');
      
      return { 
        success: true, 
        importType: 'email', 
        mnemonic,
        addresses 
      };
    } else {
      const input = (arg1 || '').toString().trim();
      if (!input) {
        const msg = getTranslation('wallet.empty_input', 'Empty input provided');
        throw new Error(msg);
      }
      
      let addresses;
      
      if (validateInput(input, 'xprv')) {
        addresses = await hdManager.importHDWallet(input);
        walletState.importType = 'hd';
        
        await keyManager.storeKey('bech32KeyPair', {
          privateKey: addresses.keyPair.privateKey.toString('hex'),
          publicKey: addresses.publicKey.toString('hex')
        });
        
        if (addresses.taprootKeyPair) {
          await keyManager.storeKey('taprootKeyPair', {
            privateKey: addresses.taprootKeyPair.privateKey.toString('hex'),
            publicKey: addresses.taprootPublicKey.toString('hex')
          });
        }
        
      } else if (validateInput(input, 'mnemonic')) {
        addresses = await hdManager.importHDWallet(input);
        walletState.importType = 'hd';
        
        await keyManager.storeKey('bech32KeyPair', {
          privateKey: addresses.keyPair.privateKey.toString('hex'),
          publicKey: addresses.publicKey.toString('hex')
        });
        
        if (addresses.taprootKeyPair) {
          await keyManager.storeKey('taprootKeyPair', {
            privateKey: addresses.taprootKeyPair.privateKey.toString('hex'),
            publicKey: addresses.taprootPublicKey.toString('hex')
          });
        }
        
      } else if (validateInput(input, 'wif')) {
        addresses = await importWIF(input);
        walletState.importType = 'single';
        
        await keyManager.storeKey('bech32KeyPair', {
          privateKey: addresses.keyPair.privateKey.toString('hex'),
          publicKey: addresses.publicKey.toString('hex')
        });
        
      } else if (validateInput(input, 'hex')) {
        addresses = await importHex(input);
        walletState.importType = 'single';
        
        await keyManager.storeKey('bech32KeyPair', {
          privateKey: addresses.keyPair.privateKey.toString('hex'),
          publicKey: addresses.publicKey.toString('hex')
        });
        
      } else {
        const msg = getTranslation('wallet.unsupported_input_format', 'Unsupported input format');
        throw new Error(msg);
      }
      
      walletState.legacyAddress = addresses.legacy;
      walletState.p2shAddress = addresses.p2sh;
      walletState.bech32Address = addresses.bech32;
      walletState.taprootAddress = addresses.taproot || '';
      walletState.walletAddress = addresses.bech32;
      
      const importType = validateInput(input, 'xprv') ? 'xprv' :
                        validateInput(input, 'mnemonic') ? 'mnemonic' :
                        validateInput(input, 'wif') ? 'wif' : 'hex';
      
      syncGlobalState();
      eventBus.emit(EVENTS.WALLET_IMPORTED, { addresses, importType });
      
      if (FEATURE_FLAGS.LOG_ADDRESSES) {
        if (walletState.importType === 'hd') {
          console.log('=== WALLET ADDRESSES (HD) ===');
          console.log('Legacy (P2PKH)  :', addresses.legacy);
          console.log('P2SH (Wrapped)  :', addresses.p2sh);
          console.log('Bech32 (Native) :', addresses.bech32);
          console.log('Bech32m (Taproot):', addresses.taproot);
          console.log('============================');
        } else {
          console.log('=== WALLET ADDRESSES (Single Key) ===');
          console.log('Legacy (P2PKH)  :', addresses.legacy);
          console.log('P2SH (Wrapped)  :', addresses.p2sh);
          console.log('Bech32 (Native) :', addresses.bech32);
          console.log('=====================================');
        }
      }
                              
      return { 
        success: true, 
        importType,
        addresses 
      };
    }
  } catch (error) {
    return { 
      success: false, 
      error: error.message || String(error) 
    };
  }
}

// === UTXO AND BALANCE FUNCTIONS ===
export async function utxos(addr, isHD = false, hdWallet = null) {
  if (window.isOperationActive && window.isOperationActive('utxo-scan')) {
    return [];
  }
  
  if (window.startOperation) window.startOperation('utxo-scan');
  
  try {
    if (isHD && hdWallet) {
      const addressType = AddressManager.getAddressType(addr);
      
      if (addressType === 'p2wpkh') {
        return await hdManager.utxosAllForBech32();
      } else if (addressType === 'p2tr') {
        return await hdManager.utxosForTaproot();
      }
    }
    
    const scan = await window.rpc('scantxoutset', ['start', [`addr(${addr})`]]);
    if (!scan.success || !scan.unspents) return [];
    
    const validUtxos = scan.unspents.map(u => {
      const scriptType = AddressManager.detectScriptType(u.scriptPubKey);
      return {
        txid: u.txid,
        vout: u.vout,
        amount: u.amount,
        scriptPubKey: u.scriptPubKey,
        scriptType
      };
    });
  
    return validUtxos;
  } catch (error) {
    throw error;
  } finally {
    if (window.endOperation) window.endOperation('utxo-scan');
  }
}

export async function balance(addr, isHD = false, hdWallet = null) {
  if (walletState._refreshBlocked) {
    return 0;
  }

  try {
    if (isHD && hdWallet) {
      const addressType = AddressManager.getAddressType(addr);
      
      if (addressType === 'p2wpkh') {
        const utxoList = await hdManager.utxosAllForBech32();
        const total = utxoList.reduce((sum, utxo) => sum + (utxo.amount || 0), 0);
        return total;
      } else if (addressType === 'p2tr') {
        const utxoList = await hdManager.utxosForTaproot();
        const total = utxoList.reduce((sum, utxo) => sum + (utxo.amount || 0), 0);
        return total;
      } else {
        const utxoList = await utxos(addr, true, hdWallet);
        const total = utxoList.reduce((sum, utxo) => sum + (utxo.amount || 0), 0);
        return total;
      }
    } else {
      const scan = await window.rpc('scantxoutset', ['start', [`addr(${addr})`]]);
      const balance = (scan && scan.total_amount) || 0;
      return balance;
    }
  } catch (error) {
    const msg = getTranslation('wallet.balance_fetch_failed', 'Failed to fetch balance: {{error}}', { error: error.message });
    throw new Error(msg);
  }
}

// === REFRESH ALL BALANCES ===
export async function refreshAllBalances() {
  if (window.isOperationActive && window.isOperationActive('full-refresh')) {
    return;
  }
  
  if (window.startOperation) window.startOperation('full-refresh');
  
  showBalanceLoadingSpinner(true, 'loading.cache_clearing');
  
  try {
    if (window.clearBlockchainCaches) {
      console.log('[REFRESH] Clearing ALL caches including UTXOs...');
      const maybePromise = window.clearBlockchainCaches();
      if (maybePromise && typeof maybePromise.then === 'function') {
        await maybePromise;
      }
    }
    
    await new Promise(r => setTimeout(r, 800));
    
    showBalanceLoadingSpinner(true, 'loading.utxo_scan');
    
    if (typeof window.updateSendTabBalance === 'function') {
      await window.updateSendTabBalance();
    }
    
    if (window.getTotalBalance) {
      const total = await window.getTotalBalance();
      const balanceElement = document.getElementById('totalBalance');
      if (balanceElement) {
        const balanceText = getTranslation('import_section.balance', 'Balance:');
        balanceElement.textContent = `${balanceText} ${total.toFixed(8)} NITO`;
      }
    }
    
    const sendTabBalance = document.getElementById('sendTabBalance');
    if (sendTabBalance && window.balance) {
      const selectedType = document.getElementById('debitAddressType')?.value || 'bech32';
      let address = '';
      if (selectedType === 'p2tr') {
        address = window.taprootAddress || '';
      } else {
        address = window.bech32Address || '';
      }
      
      if (address) {
        const isHD = window.importType === 'hd';
        const hdWallet = isHD && window.hdManager ? window.hdManager.hdWallet : null;
        const balance = await window.balance(address, isHD, hdWallet);
        sendTabBalance.textContent = (balance || 0).toFixed(8);
      }
    }
    
    showBalanceLoadingSpinner(true, 'loading.balance_updated');
    await new Promise(r => setTimeout(r, 1200));
    
  } catch (error) {
    console.error('Refresh error:', error);
    showBalanceLoadingSpinner(true, 'loading.update_error');
    await new Promise(r => setTimeout(r, 1500));
  } finally {
    showBalanceLoadingSpinner(false);
    if (window.endOperation) window.endOperation('full-refresh');
  }
}

// === WALLET STATUS FUNCTIONS ===
export function isWalletReady() {
  return walletState.isReady();
}

export function getWalletAddress() {
  return walletState.bech32Address;
}

export function getTaprootAddress() {
  return walletState.taprootAddress;
}

export async function getWalletKeyPair() {
  return await walletState.getWalletKeyPair();
}

export async function getWalletPublicKey() {
  return await walletState.getWalletPublicKey();
}

export async function getBech32Address() {
  return walletState.bech32Address;
}

export async function getTotalBalance() {
  return await walletState.updateBalance();
}

export async function getTaprootKeyPair() {
  return await walletState.getTaprootKeyPair();
}

export async function getTaprootPublicKey() {
  return await walletState.getTaprootPublicKey();
}

// === GLOBAL STATE SYNC ===
export function syncGlobalState() {
  if (typeof window !== 'undefined') {
    window.walletAddress = walletState.walletAddress;
    window.legacyAddress = walletState.legacyAddress;
    window.p2shAddress = walletState.p2shAddress;
    window.bech32Address = walletState.bech32Address;
    window.taprootAddress = walletState.taprootAddress;
    window.importType = walletState.importType;
    window.consolidateButtonInjected = walletState.consolidateButtonInjected;
    window.hdManager = hdManager;
  }
}

// === GLOBAL INSTANCES ===
export const walletState = new WalletState();
export const hdManager = new HDWalletManager();

// === GLOBAL COMPATIBILITY ===
if (typeof window !== 'undefined') {
  window.importWIF = importWIF;
  window.importHex = importHex;
  window.importWallet = importWallet;
  window.isWalletReady = isWalletReady;
  window.getWalletAddress = getWalletAddress;
  window.getTaprootAddress = getTaprootAddress;
  window.getWalletKeyPair = getWalletKeyPair;
  window.getWalletPublicKey = getWalletPublicKey;
  window.getBech32Address = getBech32Address;
  window.getTotalBalance = getTotalBalance;
  window.getTaprootKeyPair = getTaprootKeyPair;
  window.getTaprootPublicKey = getTaprootPublicKey;
  window.updateInactivityTimer = updateInactivityTimer;
  window.hdManager = hdManager;
  window.utxos = utxos;
  window.balance = balance;
  window.refreshAllBalances = refreshAllBalances;
  
  window.walletAddress = '';
  window.legacyAddress = '';
  window.p2shAddress = '';
  window.bech32Address = '';
  window.taprootAddress = '';
  window.importType = '';
  window.consolidateButtonInjected = false;
}

console.log('Wallet module loaded - Version 3.0.0');