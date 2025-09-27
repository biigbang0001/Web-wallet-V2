// Transaction Management for NITO Wallet
// Handles transaction creation, signing, and UTXO consolidation 

import { NITO_NETWORK, TRANSACTION_CONFIG, ELEMENT_IDS, OPERATION_STATE } from './config.js';
import { armInactivityTimerSafely } from './security.js';
import { eventBus, EVENTS } from './events.js';
import { waitForLibraries } from './vendor.js';

// === POLYFILL: Uint8Array.equals for bitcoinjs-lib interop ===
if (typeof Uint8Array !== 'undefined' && !Uint8Array.prototype.equals) {
  Object.defineProperty(Uint8Array.prototype, 'equals', {
    value: function(other) {
      if (!other || typeof other.length !== 'number') return false;
      if (other.length !== this.length) return false;
      let diff = 0;
      for (let i = 0; i < this.length; i++) { diff |= (this[i] ^ other[i]); }
      return diff === 0;
    },
    writable: false,
    configurable: true,
    enumerable: false
  });
}

// === BITCOIN LIBRARIES ACCESS ===
async function getBitcoinLibraries() {
  await waitForLibraries();
  
  if (!window.bitcoin || !window.ECPair) {
    throw new Error('Bitcoin libraries not properly loaded');
  }
  
  return {
    bitcoin: window.bitcoin,
    ECPair: window.ECPair
  };
}

// === WALLET INFO ACCESS ===
let walletInfoCache = null;
let lastCacheTime = 0;
const CACHE_DURATION = 2000;

async function getWalletInfo() {
  const now = Date.now();
  
  if (walletInfoCache && (now - lastCacheTime) < CACHE_DURATION) {
    return walletInfoCache;
  }
  
  if (window.isWalletReady && window.isWalletReady()) {
    const info = {
      address: window.getWalletAddress ? window.getWalletAddress() : '',
      isReady: true,
      addresses: {
        bech32: window.bech32Address || '',
        legacy: window.legacyAddress || '',
        p2sh: window.p2shAddress || '',
        taproot: window.taprootAddress || ''
      }
    };
    walletInfoCache = info;
    lastCacheTime = now;
    return info;
  }
  
  try {
    const result = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('timeout')), 1000);
      eventBus.once(EVENTS.WALLET_INFO_RESPONSE, (data) => {
        clearTimeout(timeout);
        resolve(data);
      }, { timeout: 1000 });
      eventBus.emit(EVENTS.WALLET_INFO_REQUEST);
    });
    walletInfoCache = result;
    lastCacheTime = now;
    return result;
  } catch (error) {
    return { address: '', isReady: false, addresses: {} };
  }
}

let lastTxid = null;

if (typeof window !== 'undefined') {
  window._lastConsolidationTxid = null;
}

// === FEE CALCULATION AND ESTIMATION ===
export class FeeManager {
  constructor() {
    this.minFeeRate = TRANSACTION_CONFIG.MIN_FEE_RATE;
    this.initialized = false;
  }

  async getRealFeeRate() {
    try {
      if (!window.rpc) {
        return this.minFeeRate;
      }

      const [feeInfo, mempoolInfo, networkInfo] = await Promise.allSettled([
        window.rpc('estimatesmartfee', [6]),
        window.rpc('getmempoolinfo', []),
        window.rpc('getnetworkinfo', [])
      ]);

      const estimatedRate = (feeInfo.status === 'fulfilled' && feeInfo.value && feeInfo.value.feerate) 
        ? feeInfo.value.feerate : 0;
      
      const mempoolMinFee = (mempoolInfo.status === 'fulfilled' && mempoolInfo.value && mempoolInfo.value.mempoolminfee) 
        ? mempoolInfo.value.mempoolminfee : 0;
      
      const relayFee = (networkInfo.status === 'fulfilled' && networkInfo.value && networkInfo.value.relayfee) 
        ? networkInfo.value.relayfee : 0;

      const realRate = Math.max(estimatedRate, mempoolMinFee, relayFee, this.minFeeRate);
      return realRate;
    } catch (e) {
      console.warn('[FEE] Error getting real fee rate, using minimum:', e);
      return this.minFeeRate;
    }
  }

  calculateFeeForVsize(vbytes, feeRate) {
    return Math.ceil(vbytes * (feeRate * 1e8) / 1000);
  }

  estimateVBytes(inputType, numInputs, numOutputs = 1) {
    const inputSizes = { 
      p2pkh: 148, 
      p2wpkh: 68, 
      p2sh: 91, 
      p2tr: 57.5 
    };
    const outputSize = 31;
    const overhead = 10;
    
    const inputSize = inputSizes[inputType] || inputSizes.p2wpkh;
    const totalVBytes = overhead + (inputSize * numInputs) + (outputSize * numOutputs);
    
    return totalVBytes;
  }
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
    return window.bitcoin.crypto.taggedHash(
      'TapTweak',
      Buffer.concat([TaprootUtils.toXOnly(pubKey), h])
    );
  }

  static tweakSigner(signer, opts = {}) {
    if (!window.ecc || typeof window.ecc.privateAdd !== 'function') {
      throw new Error('ECC library not available for tweakSigner');
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
      throw new Error('Invalid tweaked private key');
    }

    const PTweak = window.ecc.pointFromScalar(dTweak, true);
    if (!PTweak) {
      throw new Error('Failed to compute tweaked public key');
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
      throw new Error('Bitcoin library not available');
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
        throw new Error('Missing taproot keypair for UTXO preparation');
      }
      const xonly = TaprootUtils.toXOnly(Buffer.from(kp.publicKey));
      const enriched = { ...utxo, keyPair: kp, tapInternalKey: xonly, scriptType: (utxo.scriptType || 'p2tr') };
      return enriched;
    } catch (e) {
      throw e;
    }
  }
}

if (typeof window !== 'undefined') {
  window.TaprootUtils = TaprootUtils;
}

// === FILTER MATURE UTXOS ===
async function filterMatureUtxos(utxoList) {
  if (!Array.isArray(utxoList) || !utxoList.length) return [];
  
  const BATCH_SIZE = 5;
  const matureUtxos = [];
  
  const checkUtxoMaturity = async (txid, vout) => {
    try {
      if (!window.rpc) return null;
      
      const utxoInfo = await window.rpc('gettxout', [txid, vout, true]);
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
      return null;
    }
  };
  
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
      await new Promise(r => setTimeout(r, 50));
    }
  }
  
  return matureUtxos;
}

// === MAIN TRANSACTION BUILDER ===
export class SimpleTransactionBuilder {
  constructor() {
    this.feeManager = new FeeManager();
  }

  async signTxWithPSBT(to, amt, isConsolidation = false) {
    armInactivityTimerSafely();
    
    const walletInfo = await getWalletInfo();
    if (!walletInfo.isReady) {
      const errorMsg = window.getTranslation('errors.import_first', 'Importez d\'abord un wallet.');
      throw new Error(errorMsg);
    }

    const selectedAddressType = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE)?.value || 'bech32';
    
    let sourceAddress;
    if (selectedAddressType === 'p2tr') {
      sourceAddress = walletInfo.addresses.taproot;
    } else {
      sourceAddress = walletInfo.addresses.bech32;
    }
    
    if (!sourceAddress) {
      throw new Error(`Adresse source non trouvée pour le type: ${selectedAddressType}`);
    }
    
    if (!window.utxos) {
      const errorMsg = window.getTranslation('errors.transaction_functions_unavailable', 'Fonctions de transaction non disponibles');
      throw new Error(errorMsg);
    }

    const hdWallet = window.hdManager ? window.hdManager.hdWallet : null;
    const isHD = window.importType === 'hd';

    const rawUtxos = await window.utxos(sourceAddress, isHD, hdWallet);
    
    if (!rawUtxos.length) {
      const errorMsg = window.getTranslation('transactions.no_utxos_for_consolidation', 'Aucun UTXO disponible');
      throw new Error(errorMsg);
    }

    const matureUtxos = await filterMatureUtxos(rawUtxos);
    
    if (!matureUtxos.length) {
      const errorMsg = window.getTranslation('transactions.no_suitable_utxos', 'Aucun UTXO mature approprié disponible');
      throw new Error(errorMsg);
    }

    let workingUtxos;
    if (isConsolidation) {
      if (selectedAddressType === 'p2tr') {
        workingUtxos = matureUtxos.filter(u => u.scriptType === 'p2tr');
        workingUtxos = await Promise.all(
          workingUtxos.map(utxo => TaprootUtils.prepareTaprootUtxo(utxo))
        );
      } else {
        workingUtxos = matureUtxos.filter(u => ['p2wpkh', 'p2pkh', 'p2sh'].includes(u.scriptType));
      }
    } else {
      const filteredUtxos = window.filterOpReturnUtxos ? await window.filterOpReturnUtxos(matureUtxos) : matureUtxos;
      if (selectedAddressType === 'p2tr') {
        workingUtxos = filteredUtxos.filter(u => u.scriptType === 'p2tr');
        workingUtxos = await Promise.all(
          workingUtxos.map(utxo => TaprootUtils.prepareTaprootUtxo(utxo))
        );
      } else {
        workingUtxos = filteredUtxos.filter(u => ['p2wpkh', 'p2pkh', 'p2sh'].includes(u.scriptType));
      }
    }

    if (!workingUtxos.length) {
      const errorMsg = window.getTranslation('transactions.no_suitable_utxos', `Aucun UTXO ${selectedAddressType} mature approprié disponible`);
      throw new Error(errorMsg);
    }

    const target = Math.round(amt * 1e8);
    workingUtxos.sort((a, b) => b.amount - a.amount);

    let selectedUtxos, total;

    if (isConsolidation) {
      selectedUtxos = [...workingUtxos];
      total = selectedUtxos.reduce((s, u) => s + Math.round(u.amount * 1e8), 0);
    } else {
      selectedUtxos = [];
      total = 0;
      
      const realFeeRate = await this.feeManager.getRealFeeRate();
      
      for (const u of workingUtxos) {
        selectedUtxos.push(u);
        total += Math.round(u.amount * 1e8);
        
        const inputType = selectedAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh';
        const vbytes = this.feeManager.estimateVBytes(inputType, selectedUtxos.length);
        const estimatedFees = this.feeManager.calculateFeeForVsize(vbytes, realFeeRate);
        
        if (total >= target + estimatedFees) {
          break;
        }
      }
      
      const finalInputType = selectedAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh';
      const finalVbytes = this.feeManager.estimateVBytes(finalInputType, selectedUtxos.length);
      const finalFees = this.feeManager.calculateFeeForVsize(finalVbytes, realFeeRate);
      
      if (total < target + finalFees) {
        const shortfall = (target + finalFees - total) / 1e8;
        const errorMsg = window.getTranslation('transactions.insufficient_funds_detailed', 
          `Fonds insuffisants. Utilisez le bouton MAX ou réduisez le montant de ${shortfall.toFixed(8)} NITO pour couvrir les frais.`,
          { amount: shortfall.toFixed(8) }
        );
        throw new Error(errorMsg);
      }
    }

    return await this.buildAndSignTransaction(to, target, selectedUtxos, isConsolidation, selectedAddressType);
  }

  async buildAndSignTransaction(to, target, selectedUtxos, isConsolidation, sourceAddressType) {
    const { bitcoin } = await getBitcoinLibraries();
    
    const realFeeRate = await this.feeManager.getRealFeeRate();
    const inputType = sourceAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh';
    const outputCount = isConsolidation ? 1 : 2;
    const vbytes = this.feeManager.estimateVBytes(inputType, selectedUtxos.length, outputCount);
    const fees = this.feeManager.calculateFeeForVsize(vbytes, realFeeRate);
    
    const total = selectedUtxos.reduce((s, u) => s + Math.round(u.amount * 1e8), 0);
    const change = total - target - fees;
    
    if (change < 0) {
      const errorMsg = window.getTranslation('transactions.insufficient_funds_after_fees', 'Fonds insuffisants après calcul des frais');
      throw new Error(errorMsg);
    }

    const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
    psbt.setVersion(2);

    for (const utxo of selectedUtxos) {
      await this.addInputToPsbt(psbt, utxo, sourceAddressType);
    }

    psbt.addOutput({ address: to, value: target });

    const dustThreshold = sourceAddressType === 'p2tr' ? 330 : 294;
    if (change > dustThreshold && !isConsolidation) {
      const walletInfo = await getWalletInfo();
      const changeAddress = sourceAddressType === 'p2tr' ? walletInfo.addresses.taproot : walletInfo.addresses.bech32;
      psbt.addOutput({ address: changeAddress, value: change });
    }

    await this.signPsbtInputs(psbt, selectedUtxos, sourceAddressType);

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const hex = tx.toHex();
    
    return { hex, actualFees: fees / 1e8 };
  }

  async addInputToPsbt(psbt, utxo, addressType) {
    const scriptBuffer = Buffer.from(utxo.scriptPubKey, 'hex');
    const value = Math.round(utxo.amount * 1e8);
    
    if (utxo.scriptType === 'p2wpkh') {
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: { script: scriptBuffer, value }
      });
    } else if (utxo.scriptType === 'p2sh') {
      const redeem = utxo.redeemScript;
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: { script: scriptBuffer, value },
        redeemScript: redeem
      });
    } else if (utxo.scriptType === 'p2pkh') {
      if (!window.fetchRawTxHex) {
        throw new Error('Raw transaction fetch function not available');
      }
      const hex = await window.fetchRawTxHex(utxo.txid);
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        nonWitnessUtxo: Buffer.from(hex, 'hex')
      });
    } else if (utxo.scriptType === 'p2tr') {
      let tapInternalKey = utxo.tapInternalKey;
      
      if (!tapInternalKey && utxo.keyPair) {
        tapInternalKey = TaprootUtils.toXOnly(utxo.keyPair.publicKey);
      }
      
      if (!tapInternalKey) {
        if (window.getTaprootPublicKey) {
          const taprootPubKey = await window.getTaprootPublicKey();
          if (taprootPubKey) {
            tapInternalKey = Buffer.from(taprootPubKey);
          }
        }
      }
      
      if (!tapInternalKey) {
        throw new Error('tapInternalKey manquant pour l\'UTXO taproot');
      }
      
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: { script: scriptBuffer, value },
        tapInternalKey: tapInternalKey
      });
    } else {
      throw new Error(`Type de script non supporté: ${utxo.scriptType}`);
    }
  }

  async signPsbtInputs(psbt, selectedUtxos, addressType) {
    for (let i = 0; i < selectedUtxos.length; i++) {
      const utxo = selectedUtxos[i];
      
      if (utxo.scriptType === 'p2tr') {
        let keyPair = utxo.keyPair;
        
        if (!keyPair && window.getTaprootKeyPair) {
          keyPair = await window.getTaprootKeyPair();
        }
        
        if (!keyPair) {
          throw new Error(`KeyPair manquant pour l'UTXO taproot ${i}`);
        }
        
        const tweaked = await TaprootUtils.tweakSigner(keyPair, { network: NITO_NETWORK });
        psbt.signInput(i, tweaked);
      } else {
        let keyPair = utxo.keyPair;
        
        if (!keyPair && window.getWalletKeyPair) {
          keyPair = await window.getWalletKeyPair();
        }
        
        if (!keyPair) {
          throw new Error(`KeyPair manquant pour l'UTXO ${utxo.scriptType} ${i}`);
        }
        
        const signer = {
          network: keyPair.network,
          privateKey: Buffer.from(keyPair.privateKey),
          publicKey: Buffer.from(keyPair.publicKey),
          sign: (hash) => Buffer.from(keyPair.sign(hash))
        };
        
        psbt.signInput(i, signer);
      }
    }
  }
}

// === CONSOLIDATE UTXOS ===
export async function consolidateUtxos() {
  if (window.isOperationActive && window.isOperationActive('consolidation')) {
    alert('Consolidation déjà en cours. Veuillez attendre.');
    return;
  }

  if (window.startOperation) window.startOperation('consolidation');
  armInactivityTimerSafely();
  console.log('[CONSOLIDATION] Starting consolidation...');

  try {
    const walletInfo = await getWalletInfo();
    if (!walletInfo.isReady) {
      const alertMsg = window.getTranslation('errors.import_first', 'Importez d\'abord un wallet.');
      alert(alertMsg);
      return;
    }

    const sourceType = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE)?.value || 'bech32';

    const spinner = document.getElementById(ELEMENT_IDS.LOADING_SPINNER);
    if (spinner) spinner.style.display = 'block';

    if (!window.utxos) {
      const errorMsg = window.getTranslation('errors.transaction_functions_unavailable', 'Fonctions de transaction non disponibles');
      throw new Error(errorMsg);
    }

    const hdWallet = window.hdManager ? window.hdManager.hdWallet : null;
    const isHD = window.importType === 'hd';

    let rawUtxos = [];
    
    if (sourceType === 'p2tr') {
      const taprootAddress = walletInfo.addresses.taproot;
      
      if (!taprootAddress) {
        throw new Error('Adresse taproot non disponible');
      }
      
      rawUtxos = await window.utxos(taprootAddress, isHD, hdWallet);
      rawUtxos = rawUtxos.filter(u => u.scriptType === 'p2tr');
      
      rawUtxos = await Promise.all(
        rawUtxos.map(utxo => TaprootUtils.prepareTaprootUtxo(utxo))
      );
      
    } else {
      const bech32Address = walletInfo.addresses.bech32;
      
      if (isHD && hdWallet) {
        rawUtxos = await window.utxos(bech32Address, true, hdWallet);
        rawUtxos = rawUtxos.filter(u => ['p2wpkh', 'p2pkh', 'p2sh'].includes(u.scriptType));
      } else {
        rawUtxos = await window.utxos(bech32Address, false, null);
        rawUtxos = rawUtxos.filter(u => u.scriptType === 'p2wpkh');
      }
    }

    const allUtxos = await filterMatureUtxos(rawUtxos);
    
    if (allUtxos.length < 2) {
      if (spinner) spinner.style.display = 'none';
      const alertMsg = window.getTranslation('transactions.need_at_least_utxos',
        `Besoin d'au moins 2 UTXOs matures pour consolider. Trouvés: ${allUtxos.length}`,
        { count: 2, found: allUtxos.length }
      );
      alert(alertMsg);
      return;
    }

    const totalValue = allUtxos.reduce((sum, u) => sum + u.amount, 0);

    const MAX_UTXOS_PER_BATCH = sourceType === 'p2tr' ? 1000 : 1500;
    const batches = [];
    
    for (let i = 0; i < allUtxos.length; i += MAX_UTXOS_PER_BATCH) {
      const batch = allUtxos.slice(i, i + MAX_UTXOS_PER_BATCH);
      batches.push(batch);
    }

    const confirmMsg = window.getTranslation('transactions.consolidation_confirm',
      `Consolider ${allUtxos.length} UTXOs → ${batches.length} UTXO(s)\nTotal: ${totalValue.toFixed(8)} NITO\nType: ${sourceType}\n\nConfirmer?`,
      { 
        count: allUtxos.length, 
        batches: batches.length, 
        total: totalValue.toFixed(8), 
        type: sourceType 
      }
    );

    const confirmed = confirm(confirmMsg);

    if (!confirmed) {
      if (spinner) spinner.style.display = 'none';
      return;
    }

    const transactionBuilder = new SimpleTransactionBuilder();
    const txids = [];

    const destinationAddress = sourceType === 'p2tr' ? walletInfo.addresses.taproot : walletInfo.addresses.bech32;

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      const batchTotal = batch.reduce((sum, u) => sum + u.amount, 0);
      
      const realFeeRate = await transactionBuilder.feeManager.getRealFeeRate();
      const inputType = sourceType === 'p2tr' ? 'p2tr' : 'p2wpkh';
      const vbytes = transactionBuilder.feeManager.estimateVBytes(inputType, batch.length, 1);
      const estimatedFee = transactionBuilder.feeManager.calculateFeeForVsize(vbytes, realFeeRate) / 1e8;
      const netAmount = batchTotal - estimatedFee;

      if (netAmount <= 0) {
        console.warn(`[CONSOLIDATION] Batch ${i + 1} skipped - insufficient funds after fees`);
        continue;
      }

      try {
        const result = await transactionBuilder.buildAndSignTransaction(
          destinationAddress, 
          Math.round(netAmount * 1e8), 
          batch, 
          true, 
          sourceType
        );
        
        if (!window.rpc) {
          const errorMsg = window.getTranslation('errors.rpc_unavailable', 'Fonction RPC non disponible');
          throw new Error(errorMsg);
        }
        
        const txid = await window.rpc('sendrawtransaction', [result.hex]);
        txids.push(txid);
        
        if (i === batches.length - 1) {
          lastTxid = txid;
          if (window._lastConsolidationTxid !== undefined) {
            window._lastConsolidationTxid = txid;
          }
          if (window.lastTxid !== undefined) {
            window.lastTxid = txid;
          }
        }
        
      } catch (error) {
        console.error(`[CONSOLIDATION] Batch ${i + 1} failed:`, error);
        throw error;
      }
    }

    if (spinner) spinner.style.display = 'none';

    const finalTxid = txids[txids.length - 1];
    if (finalTxid && window.showSuccessPopup) {
      await window.showSuccessPopup(finalTxid);
    }

    const successMsg = window.getTranslation('transactions.consolidation_completed',
      `Consolidation terminée!\n${allUtxos.length} UTXOs → ${txids.length} UTXO(s)\nTransactions: ${txids.length}\nType: ${sourceType}`,
      { 
        original: allUtxos.length, 
        final: txids.length, 
        txCount: txids.length, 
        type: sourceType 
      }
    );

    alert(successMsg);
    
    console.log(`[CONSOLIDATION] Completed successfully: ${txids.length} transactions`);
    
    setTimeout(() => {
      const refreshBtn = document.getElementById(ELEMENT_IDS.REFRESH_BALANCE_BUTTON);
      if (refreshBtn) refreshBtn.click();
    }, 8000);

  } catch (e) {
    const spinner = document.getElementById(ELEMENT_IDS.LOADING_SPINNER);
    if (spinner) spinner.style.display = 'none';
    
    const errorMsg = window.getTranslation('transactions.consolidation_error', 
      `Erreur de consolidation: ${e.message}`,
      { error: e.message }
    );
    alert(errorMsg);
    console.error('[CONSOLIDATION] Error:', e);
  } finally {
    if (window.endOperation) window.endOperation('consolidation');
  }
}

// === TRANSFER TO P2SH ADDRESS ===
export async function transferToP2SH(amt) {
  armInactivityTimerSafely();
  
  if (!window.getWalletPublicKey) {
    const errorMsg = window.getTranslation('errors.import_first', 'Importez d\'abord un wallet.');
    throw new Error(errorMsg);
  }
  
  const walletPublicKey = await window.getWalletPublicKey();
  if (!walletPublicKey) {
    throw new Error('Wallet public key not available');
  }
  
  const { bitcoin } = await getBitcoinLibraries();
  const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(walletPublicKey), network: NITO_NETWORK });
  const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh, network: NITO_NETWORK });
  
  const transactionBuilder = new SimpleTransactionBuilder();
  return await transactionBuilder.signTxWithPSBT(p2sh.address, amt);
}

const transactionBuilder = new SimpleTransactionBuilder();

export async function signTx(to, amt, isConsolidation = false) {
  return await transactionBuilder.signTxWithPSBT(to, amt, isConsolidation);
}

export async function signTxWithPSBT(to, amt, isConsolidation = false) {
  return await transactionBuilder.signTxWithPSBT(to, amt, isConsolidation);
}

export async function signTxBatch(to, amt, specificUtxos, isConsolidation = true) {
  return await transactionBuilder.buildAndSignTransaction(to, Math.round(amt * 1e8), specificUtxos, isConsolidation, 'bech32');
}

export function feeForVsize(vbytes) {
  const feeManager = new FeeManager();
  return feeManager.calculateFeeForVsize(vbytes, TRANSACTION_CONFIG.MIN_FEE_RATE);
}

export function effectiveFeeRate() {
  return TRANSACTION_CONFIG.MIN_FEE_RATE;
}

if (typeof window !== 'undefined') {
  window.signTx = signTx;
  window.signTxWithPSBT = signTxWithPSBT;
  window.signTxBatch = signTxBatch;
  window.transferToP2SH = transferToP2SH;
  window.consolidateUtxos = consolidateUtxos;
  window.feeForVsize = feeForVsize;
  window.effectiveFeeRate = effectiveFeeRate;
}

console.log('transactions module loaded - Version 2.0.0');
