// Wallet Management for NITO Wallet

import { NITO_NETWORK, HD_CONFIG, SECURITY_CONFIG, ELEMENT_IDS, FEATURE_FLAGS } from './config.js';
import { keyManager, validateInput, deriveFromCredentials, armInactivityTimerSafely } from './security.js';
import { eventBus, EVENTS } from './events.js';
import { waitForLibraries } from './vendor.js';

// === GLOBAL STATE ===
let lastTxid = null;
window._lastConsolidationTxid = null;
let _successPopupEl = null;
let _successPopupTimer = null;
let _pendingConfirmations = new Set();
let _refreshBlocked = false;

// === BITCOIN LIBRARY SAFE ACCESS ===
async function getBitcoinLibraries() {
  await waitForLibraries();
  
  if (!window.bitcoin || !window.ECPair || !window.bip39 || !window.bip32) {
    throw new Error('Bitcoin libraries not properly loaded');
  }
  
  return {
    bitcoin: window.bitcoin,
    ECPair: window.ECPair,
    bip39: window.bip39,
    bip32: window.bip32
  };
}

// === EXPLORER AND CONFIRMATION UTILITIES ===
async function getExplorerUrl(txid) {
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

async function checkTransactionConfirmation(txid) {
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

// === SUCCESS POPUP SYSTEM ===
async function showSuccessPopup(txid) {
  armInactivityTimerSafely();
  
  try {
    if (_successPopupTimer) { clearTimeout(_successPopupTimer); _successPopupTimer = null; }
    if (_successPopupEl && _successPopupEl.parentNode) { _successPopupEl.parentNode.removeChild(_successPopupEl); }
  } catch (_) {}

  _pendingConfirmations.add(txid);
  _refreshBlocked = true;

  const t = window.getTranslation || ((key, fallback) => fallback || key);

  const refreshBtn = document.getElementById(ELEMENT_IDS.REFRESH_BALANCE_BUTTON);
  if (refreshBtn) {
    refreshBtn.disabled = true;
    refreshBtn.textContent = t('popup.confirming', 'Confirming...');
  }

  const body = document.body;
  const isDarkMode = body.getAttribute('data-theme') === 'dark';
  let progress = 0;
  let explorerUrl;
  try {
    explorerUrl = await getExplorerUrl(txid);
  } catch (_) { explorerUrl = "#"; }

  const popup = document.createElement('div');
  popup.className = 'popup';
  popup.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: ${isDarkMode ? '#1a202c' : '#ffffff'};
    color: ${isDarkMode ? '#e2e8f0' : '#1e3a8a'};
    padding: 24px;
    border: 1px solid ${isDarkMode ? '#4a5568' : '#e2e8f0'};
    border-radius: 20px;
    box-shadow: 0 15px 40px rgba(0,0,0,${isDarkMode ? '0.6' : '0.25'});
    z-index: 100000;
    pointer-events: auto;
    min-width: 380px;
    max-width: 90vw;
    backdrop-filter: blur(15px);
    border: 2px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'};
  `;

  const _sanitize = (html) => (typeof DOMPurify !== "undefined" && DOMPurify && DOMPurify.sanitize) ? DOMPurify.sanitize(html) : html;

  const successMessage = t('popup.success_message', 'Transaction sent successfully!');
  const confirmationProgress = t('popup.confirmation_progress', 'Confirmation:');
  const transactionId = t('popup.transaction_id', 'Transaction ID:');
  const closeButton = t('popup.close_button', 'Close');

  popup.innerHTML = _sanitize(`
    <div style="text-align: center;">
      <div style="font-size: 2.5rem; margin-bottom: 1rem;">✅</div>
      <p style="margin-bottom: 20px; font-weight: 700; font-size: 18px; color: ${isDarkMode ? '#4ade80' : '#10b981'};">${successMessage}</p>
      <p style="margin-bottom: 15px; font-size: 16px; font-weight: 600;">${confirmationProgress} <span id="progress" style="font-weight: bold; color: ${isDarkMode ? '#60a5fa' : '#2563eb'};">0</span>%</p>
      <div style="width: 100%; background: ${isDarkMode ? '#374151' : '#e5e7eb'}; border-radius: 12px; height: 10px; margin: 15px 0; overflow: hidden; box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);">
        <div id="progressBar" style="width: 0%; background: linear-gradient(90deg, ${isDarkMode ? '#4ade80' : '#10b981'}, ${isDarkMode ? '#22d3ee' : '#06b6d4'}); height: 100%; border-radius: 12px; transition: width 0.5s ease; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></div>
      </div>
      <div style="margin-bottom: 20px; padding: 12px; background: ${isDarkMode ? '#374151' : '#f8fafc'}; border-radius: 10px; border: 1px solid ${isDarkMode ? '#4b5563' : '#e2e8f0'};">
        <p style="margin-bottom: 8px; font-size: 14px; font-weight: 600; color: ${isDarkMode ? '#9ca3af' : '#6b7280'};">${transactionId}</p>
        <p id="txidLink" style="font-size: 13px; word-break: break-all; font-family: 'Monaco', 'Menlo', 'Consolas', monospace; color: ${isDarkMode ? '#d1d5db' : '#374151'};">${txid}</p>
      </div>
      <button id="closeSuccessPopup" type="button" style="
        background: ${isDarkMode ? '#3b82f6' : '#2563eb'}; 
        color: white; 
        border: none; 
        padding: 12px 24px; 
        border-radius: 10px; 
        cursor: pointer; 
        font-weight: 700; 
        font-size: 16px; 
        transition: all 0.3s ease;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
      ">${closeButton}</button>
    </div>
  `);
  document.body.appendChild(popup);
  _successPopupEl = popup;

  const progressSpan = popup.querySelector('#progress');
  const progressBar = popup.querySelector('#progressBar');
  const txidLinkSpan = popup.querySelector('#txidLink');
  const closeButtonEl = popup.querySelector('#closeSuccessPopup');

  const clearAll = async () => {
    try { if (_successPopupTimer) clearTimeout(_successPopupTimer); } catch(_) {}
    _successPopupTimer = null;
    if (_successPopupEl && _successPopupEl.parentNode) {
      _successPopupEl.parentNode.removeChild(_successPopupEl);
    }
    _successPopupEl = null;
    
    _pendingConfirmations.delete(txid);
    if (_pendingConfirmations.size === 0) {
      _refreshBlocked = false;
      if (refreshBtn) {
        refreshBtn.disabled = false;
        const refreshText = t('import_section.refresh_button', 'Refresh');
        refreshBtn.textContent = refreshText;
      }
    }

    if (progress >= 100) {
      console.log('[POPUP] Transaction was confirmed, starting intelligent refresh...');
      
      setTimeout(async () => {
        if (window.refreshAllBalances) {
          let balanceFound = false;
          
          for (let attempt = 1; attempt <= 3; attempt++) {
            console.log(`[POPUP] Balance refresh attempt ${attempt}/3 after popup close...`);
            
            await window.refreshAllBalances();
            
            if (window.getTotalBalance) {
              const currentBalance = await window.getTotalBalance();
              console.log(`[POPUP] Current balance: ${currentBalance.toFixed(8)} NITO`);
              
              if (currentBalance > 0) {
                console.log(`[POPUP] Balance refreshed successfully on attempt ${attempt}`);
                balanceFound = true;
                break;
              }
            }
            
            if (attempt < 3) {
              console.log(`[POPUP] Balance still 0, waiting 3 seconds before retry...`);
              await new Promise(resolve => setTimeout(resolve, 3000));
            }
          }
          
          if (!balanceFound) {
            console.log(`[POPUP] Balance still 0 after 3 attempts, UTXOs may need more time to be indexed`);
          }
        }
      }, 500);
    }
  };

  const updateProgress = async () => {
    if (progress >= 100) return;
    progress = Math.min(progress + 1.67, 100);
    if (progressSpan) progressSpan.textContent = Math.round(progress);
    if (progressBar) progressBar.style.width = Math.round(progress) + '%';
    
    try {
      const confirmed = await checkTransactionConfirmation(txid);
      if (confirmed) {
        progress = 100;
        if (progressSpan) {
          progressSpan.textContent = progress;
          progressSpan.style.color = isDarkMode ? '#4ade80' : '#10b981';
        }
        if (progressBar) {
          progressBar.style.width = '100%';
          progressBar.style.background = isDarkMode ? '#4ade80' : '#10b981';
        }
        if (txidLinkSpan) {
          txidLinkSpan.innerHTML = `<a href="${explorerUrl}" target="_blank" rel="noopener noreferrer" style="color: ${isDarkMode ? '#60a5fa' : '#2563eb'}; text-decoration: underline; font-weight: 600;">${txid}</a>`;
        }
        
        return;
      }
    } catch (_) {}
    _successPopupTimer = setTimeout(updateProgress, 10000);
  };

  updateProgress();

  if (closeButtonEl) {
    closeButtonEl.onclick = (e) => { e.preventDefault(); e.stopPropagation(); clearAll(); };
    closeButtonEl.onmouseover = () => { closeButtonEl.style.transform = 'translateY(-2px)'; closeButtonEl.style.boxShadow = '0 6px 16px rgba(59, 130, 246, 0.6)'; };
    closeButtonEl.onmouseout = () => { closeButtonEl.style.transform = 'translateY(0)'; closeButtonEl.style.boxShadow = '0 4px 12px rgba(59, 130, 246, 0.4)'; };
  }
  
  const onKey = (e) => {
    if (e.key === 'Escape') { clearAll(); document.removeEventListener('keydown', onKey); }
  };
  document.addEventListener('keydown', onKey);
}

// === TAPROOT UTILITIES ===
export class TaprootUtils {
  static toXOnly(pubkey) {
    if (!pubkey || pubkey.length < 33) {
      throw new Error('Invalid public key for X-only conversion');
    }
    return Buffer.from(pubkey.slice(1, 33));
  }

  static tapTweakHash(pubKey, h = Buffer.alloc(0)) {
    if (!window.bitcoin || !window.bitcoin.crypto) {
      throw new Error('Bitcoin library not available for tapTweakHash');
    }
    return window.bitcoin.crypto.taggedHash('TapTweak', Buffer.concat([TaprootUtils.toXOnly(pubKey), h]));
  }

  static tweakSigner(signer, opts = {}) {
    if (!window.bitcoin || !window.bitcoin.crypto) {
      throw new Error('Bitcoin library not available for tweakSigner');
    }

    let privateKey = Uint8Array.from(signer.privateKey);
    const publicKey = Uint8Array.from(signer.publicKey);
    
    if (publicKey[0] === 3) {
      privateKey = window.bitcoin.crypto.privateNegate(privateKey);
    }
    
    const tweakHash = opts.tweakHash ? Buffer.from(opts.tweakHash) : Buffer.alloc(0);
    const tweak = Uint8Array.from(TaprootUtils.tapTweakHash(signer.publicKey, tweakHash));
    const tweakedPrivateKey = window.bitcoin.crypto.privateAdd(privateKey, tweak);
    
    if (!tweakedPrivateKey) {
      throw new Error('Invalid tweaked private key');
    }
    
    const tweakedPublicKey = window.bitcoin.crypto.pointFromScalar(tweakedPrivateKey, true);
    
    return {
      publicKey: tweakedPublicKey,
      signSchnorr: (hash) => {
        const randomBytes = crypto.getRandomValues(new Uint8Array(32));
        return window.bitcoin.crypto.signSchnorr(hash, tweakedPrivateKey, randomBytes);
      }
    };
  }

  static async createTaprootAddress(publicKey, network) {
    try {
      if (!window.bitcoin || !window.bitcoin.payments) {
        throw new Error('Bitcoin library not available');
      }

      const internalPubkey = TaprootUtils.toXOnly(publicKey);
      const payment = window.bitcoin.payments.p2tr({ 
        internalPubkey: internalPubkey, 
        network: network 
      });
      
      return {
        address: payment.address,
        output: payment.output,
        internalPubkey: internalPubkey
      };
    } catch (error) {
      throw error;
    }
  }
}

// === ADDRESS MANAGEMENT ===
class AddressManager {
  static getAddressType(addr) {
    try {
      if (!addr || typeof addr !== 'string') return 'unknown';
      if (addr.startsWith('nito1p')) return 'p2tr';
      if (addr.startsWith('nito1')) return 'p2wpkh';
      if (addr.startsWith('3')) return 'p2sh';
      if (addr.startsWith('1')) return 'p2pkh';
      return 'unknown';
    } catch (e) {
      return 'unknown';
    }
  }

  static detectScriptType(scriptPubKey) {
    try {
      const script = Buffer.from(scriptPubKey, 'hex');
      if (script.length === 25 && script[0] === 0x76 && script[1] === 0xa9 && script[2] === 0x14 && script[23] === 0x88 && script[24] === 0xac) {
        return 'p2pkh';
      } else if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
        return 'p2wpkh';
      } else if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
        return 'p2sh';
      } else if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
        return 'p2tr';
      }
      return 'unknown';
    } catch (e) {
      return 'unknown';
    }
  }
}

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
      throw new Error('Failed to generate mnemonic phrase');
    }
  }

  async importHDWallet(seedOrXprv, passphrase = '') {
    if (window.isOperationActive && window.isOperationActive('wallet-import')) {
      throw new Error('Wallet import already in progress');
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
          throw new Error('Invalid mnemonic phrase');
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
      throw new Error(`HD wallet import failed: ${error.message}`);
    } finally {
      if (window.endOperation) window.endOperation('wallet-import');
    }
  }

  deriveMainAddresses() {
    if (!this.hdWallet) {
      throw new Error('HD wallet not initialized');
    }

    try {
      const { bitcoin, ECPair } = window;
      if (!bitcoin || !ECPair) {
        throw new Error('Bitcoin libraries not available');
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
        console.warn('Invalid Taproot address generated:', result.taproot);
      }

      return result;
    } catch (error) {
      throw new Error(`Failed to derive addresses: ${error.message}`);
    }
  }

  getHdAccountNode(family) {
    if (!this.hdWallet) {
      throw new Error('HD wallet not initialized');
    }
    
    const path = HD_CONFIG.DERIVATION_PATHS[family];
    if (!path) {
      throw new Error(`Unknown address family: ${family}`);
    }
    
    return this.hdWallet.derivePath(path);
  }

  deriveKeyFor(family, branch, index) {
    if (!window.bitcoin || !window.ECPair) {
      throw new Error('Bitcoin libraries not available');
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
        console.warn(`Error scanning chunk ${chunk} for ${family}:`, e);
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
        console.warn(`Failed to scan ${fam}:`, e);
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

// === ADDRESS GENERATION FUNCTIONS ===
export async function genAddr(type) {
  try {
    if (!['legacy', 'p2sh', 'bech32'].includes(type)) {
      throw new Error('Invalid address type');
    }

    const { bitcoin, ECPair } = await getBitcoinLibraries();
    
    const kp = ECPair.makeRandom({ network: NITO_NETWORK });
    const privateKeyHex = Buffer.from(kp.privateKey).toString('hex');
    const pubkeyBuffer = Buffer.from(kp.publicKey);
    
    let address;
    
    if (type === 'legacy') {
      address = bitcoin.payments.p2pkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK }).address;
    } else if (type === 'p2sh') {
      const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK });
      address = bitcoin.payments.p2sh({ redeem: p2wpkh, network: NITO_NETWORK }).address;
    } else {
      address = bitcoin.payments.p2wpkh({ pubkey: pubkeyBuffer, network: NITO_NETWORK }).address;
    }
    
    return { 
      address, 
      privateKeyHex, 
      privateKey: kp.toWIF() 
    };
  } catch (error) {
    throw error;
  }
}

export async function importWIF(wif) {
  try {
    if (!validateInput(wif, 'wif')) {
      throw new Error('Invalid WIF format');
    }

    const { bitcoin, ECPair } = await getBitcoinLibraries();

    let kp = ECPair.fromWIF(wif, NITO_NETWORK);
    
    if (!kp.publicKey || kp.publicKey.length !== 33) {
      if (!kp.privateKey) throw new Error('WIF without private key');
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
    throw new Error(`Invalid WIF: ${error.message}`);
  }
}

export async function importHex(hex) {
  try {
    if (!validateInput(hex, 'hex')) {
      throw new Error('Invalid hex format - must be 64 characters');
    }

    const { bitcoin, ECPair } = await getBitcoinLibraries();

    const privateKeyBuffer = Buffer.from(hex, 'hex');
    if (privateKeyBuffer.length !== 32) {
      throw new Error('Private key must be 32 bytes');
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
    throw new Error(`Invalid private key: ${error.message}`);
  }
}

// === UNIFIED IMPORT FUNCTION ===
export async function importWallet(arg1, arg2) {
  try {
    if (typeof arg2 === 'string' && typeof arg1 === 'string') {
      const email = arg1.trim().toLowerCase();
      const password = arg2.trim();
      
      if (!email || !password) {
        throw new Error('Missing email or password');
      }
      
      if (!validateInput(email, 'email')) {
        throw new Error('Invalid email format');
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
      
      console.log('Email wallet connected successfully');
      
      return { 
        success: true, 
        importType: 'email', 
        mnemonic,
        addresses 
      };
    } else {
      const input = (arg1 || '').toString().trim();
      if (!input) {
        throw new Error('Empty input provided');
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
        throw new Error('Unsupported input format');
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
  if (_refreshBlocked) {
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
    throw new Error(`Failed to fetch balance: ${error.message}`);
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

// === INACTIVITY TIMER ===
export function updateInactivityTimer() {
  walletState.updateLastActionTime();
  
  if (walletState.timerInterval) {
    clearInterval(walletState.timerInterval);
  }
  
  const timerElement = document.getElementById(ELEMENT_IDS.INACTIVITY_TIMER);
  if (!timerElement) return;

  const updateTimer = () => {
    if (!walletState.lastActionTime) {
      timerElement.textContent = '[10:00]';
      return;
    }
    
    const now = Date.now();
    const elapsed = now - walletState.lastActionTime;
    const remaining = Math.max(0, SECURITY_CONFIG.INACTIVITY_TIMEOUT - elapsed);
    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    
    timerElement.textContent = `[${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}]`;
    
    if (remaining <= 0) {
      clearInterval(walletState.timerInterval);
    }
  };

  updateTimer();
  walletState.timerInterval = setInterval(updateTimer, 1000);
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
  window.genAddr = genAddr;
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
  window.showSuccessPopup = showSuccessPopup;
  
  window.walletAddress = '';
  window.legacyAddress = '';
  window.p2shAddress = '';
  window.bech32Address = '';
  window.taprootAddress = '';
  window.importType = '';
  window.consolidateButtonInjected = false;
}

console.log('Wallet module loaded - Version 2.0.0');
