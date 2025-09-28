// Transaction Management for NITO Wallet

import { NITO_NETWORK, TRANSACTION_CONFIG, ELEMENT_IDS, OPERATION_STATE } from './config.js';
import { armInactivityTimerSafely } from './security.js';
import { eventBus, EVENTS } from './events.js';
import { waitForLibraries } from './vendor.js';

// === UTXO PROTECTION ===
const UTXO_PROTECTION = {
  MIN_TRANSACTION_UTXO: 0.00000777,
  MIN_TRANSACTION_UTXO_SATS: 777
};

function filterUtxosByContext(utxos, context = 'normal') {
  if (!Array.isArray(utxos)) {
    return { usableUtxos: [], protectedUtxos: [] };
  }

  const usableUtxos = [];
  const protectedUtxos = [];

  for (const utxo of utxos) {
    const amount = typeof utxo.amount === 'number' ? utxo.amount : parseFloat(utxo.amount) || 0;

    if (context === 'consolidation') {
      usableUtxos.push(utxo);
    } else {
      if (amount >= UTXO_PROTECTION.MIN_TRANSACTION_UTXO) {
        usableUtxos.push(utxo);
      } else {
        protectedUtxos.push(utxo);
      }
    }
  }

  return { usableUtxos, protectedUtxos };
}

// === POLYFILL ===
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
    this.lastFeeRate = null;
    this.lastFeeTime = 0;
    this.CACHE_DURATION = 30000;
  }

  async getRealFeeRate() {
    const now = Date.now();
    
    if (this.lastFeeRate && (now - this.lastFeeTime) < this.CACHE_DURATION) {
      return this.lastFeeRate;
    }

    try {
      if (!window.rpc) {
        this.lastFeeRate = this.minFeeRate;
        this.lastFeeTime = now;
        return this.minFeeRate;
      }

      const [feeInfo, mempoolInfo, networkInfo] = await Promise.allSettled([
        this.timeoutPromise(window.rpc('estimatesmartfee', [6]), 5000),
        this.timeoutPromise(window.rpc('getmempoolinfo', []), 5000),
        this.timeoutPromise(window.rpc('getnetworkinfo', []), 5000)
      ]);

      let estimatedRate = this.minFeeRate;
      let mempoolMinFee = this.minFeeRate;
      let relayFee = this.minFeeRate;

      if (feeInfo.status === 'fulfilled' && feeInfo.value && feeInfo.value.feerate) {
        estimatedRate = Math.max(feeInfo.value.feerate, this.minFeeRate);
      }

      if (mempoolInfo.status === 'fulfilled' && mempoolInfo.value && mempoolInfo.value.mempoolminfee) {
        mempoolMinFee = Math.max(mempoolInfo.value.mempoolminfee, this.minFeeRate);
      }

      if (networkInfo.status === 'fulfilled' && networkInfo.value && networkInfo.value.relayfee) {
        relayFee = Math.max(networkInfo.value.relayfee, this.minFeeRate);
      }

      const realRate = Math.max(estimatedRate, mempoolMinFee, relayFee, this.minFeeRate);
      const safeRate = Math.round(realRate * 1.15 * 1e8) / 1e8;
      
      this.lastFeeRate = safeRate;
      this.lastFeeTime = now;
      
      console.log(`[FEE] Rates - estimated: ${estimatedRate}, mempool: ${mempoolMinFee}, relay: ${relayFee}, final: ${safeRate}`);
      
      return safeRate;
    } catch (e) {
      console.warn('[FEE] Error getting fee rate, using safe minimum:', e);
      const safeMinRate = Math.round(this.minFeeRate * 1.5 * 1e8) / 1e8;
      this.lastFeeRate = safeMinRate;
      this.lastFeeTime = now;
      return safeMinRate;
    }
  }

  timeoutPromise(promise, timeoutMs) {
    return Promise.race([
      promise,
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Timeout')), timeoutMs)
      )
    ]);
  }

  calculateFeeForVsize(vbytes, feeRate) {
    const feeSats = Math.ceil(vbytes * (feeRate * 1e8) / 1000);
    const minFeeSats = Math.ceil(vbytes * (this.minFeeRate * 1e8) / 1000);
    const finalFee = Math.max(feeSats, minFeeSats);
    return Math.ceil(finalFee * 1.02);
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
    
    return Math.ceil(totalVBytes);
  }

  async getGuaranteedFee(inputType, numInputs, numOutputs = 2) {
    const feeRate = await this.getRealFeeRate();
    const vbytes = this.estimateVBytes(inputType, numInputs, numOutputs);
    const feeSats = this.calculateFeeForVsize(vbytes, feeRate);
    
    return {
      vbytes,
      feeSats,
      feeNito: feeSats / 1e8,
      feeRate
    };
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

// === WAIT FOR TRANSACTION CONFIRMATION ===
async function waitForTransactionConfirmation(txid, maxWaitTime = 300000) {
  const startTime = Date.now();
  
  while (Date.now() - startTime < maxWaitTime) {
    try {
      if (!window.rpc) {
        await new Promise(resolve => setTimeout(resolve, 5000));
        continue;
      }
      
      const txInfo = await window.rpc('gettransaction', [txid]);
      if (txInfo && txInfo.confirmations && txInfo.confirmations >= 1) {
        console.log(`[TX-CONFIRM] Transaction ${txid.substring(0, 8)}... confirmed`);
        return true;
      }
      
      await new Promise(resolve => setTimeout(resolve, 10000));
    } catch (error) {
      await new Promise(resolve => setTimeout(resolve, 10000));
    }
  }
  
  console.warn(`[TX-CONFIRM] Timeout waiting for confirmation of ${txid.substring(0, 8)}...`);
  return false;
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

// === OPTIMIZED UTXO SELECTION FOR MAX ===
function selectOptimalUtxosForMax(utxos, inputType, feeManager, realFeeRate) {
  const sortedUtxos = [...utxos].sort((a, b) => b.amount - a.amount);
  
  let bestSelection = [sortedUtxos[0]];
  let bestNetAmount = 0;
  
  const dustThreshold = inputType === 'p2tr' ? 330 : 294;
  
  for (let count = 1; count <= sortedUtxos.length; count++) {
    const selection = sortedUtxos.slice(0, count);
    const totalSats = selection.reduce((s, u) => s + Math.round(u.amount * 1e8), 0);
    
    const vbytesWithChange = feeManager.estimateVBytes(inputType, count, 2);
    const vbytesNoChange = feeManager.estimateVBytes(inputType, count, 1);
    
    const feesWithChange = feeManager.calculateFeeForVsize(vbytesWithChange, realFeeRate);
    const feesNoChange = feeManager.calculateFeeForVsize(vbytesNoChange, realFeeRate);
    
    const changeAmount = totalSats - feesWithChange;
    const netWithChange = changeAmount > dustThreshold ? totalSats - feesWithChange : 0;
    const netNoChange = totalSats - feesNoChange;
    
    const netAmount = Math.max(netWithChange, netNoChange);
    
    if (netAmount > bestNetAmount) {
      bestNetAmount = netAmount;
      bestSelection = [...selection];
    }
    
    if (count > 50 && netAmount < bestNetAmount * 0.99) {
      break;
    }
  }
  
  return bestSelection;
}

// === CALCULATE MAXIMUM SENDABLE AMOUNT ===
export async function calculateMaxSendableAmount() {
  armInactivityTimerSafely();
  
  const walletInfo = await getWalletInfo();
  if (!walletInfo.isReady) {
    return 0;
  }

  const selectedAddressType = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE)?.value || 'bech32';
  
  let sourceAddress;
  if (selectedAddressType === 'p2tr') {
    sourceAddress = walletInfo.addresses.taproot;
  } else {
    sourceAddress = walletInfo.addresses.bech32;
  }
  
  if (!sourceAddress || !window.utxos) {
    return 0;
  }

  try {
    const hdWallet = window.hdManager ? window.hdManager.hdWallet : null;
    const isHD = window.importType === 'hd';

    const rawUtxos = await window.utxos(sourceAddress, isHD, hdWallet);
    
    if (!rawUtxos.length) {
      return 0;
    }

    const matureUtxos = await filterMatureUtxos(rawUtxos);
    
    if (!matureUtxos.length) {
      return 0;
    }

    let workingUtxos;
    if (selectedAddressType === 'p2tr') {
      workingUtxos = matureUtxos.filter(u => u.scriptType === 'p2tr');
      workingUtxos = await Promise.all(
        workingUtxos.map(utxo => TaprootUtils.prepareTaprootUtxo(utxo))
      );
    } else {
      workingUtxos = matureUtxos.filter(u => ['p2wpkh', 'p2pkh', 'p2sh'].includes(u.scriptType));
    }

    if (!workingUtxos.length) {
      return 0;
    }

    const filtered = filterUtxosByContext(workingUtxos, 'max');
    
    if (!filtered.usableUtxos.length) {
      return 0;
    }

    const feeManager = new FeeManager();
    const inputType = selectedAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh';
    const realFeeRate = await feeManager.getRealFeeRate();
    
    const optimalUtxos = selectOptimalUtxosForMax(filtered.usableUtxos, inputType, feeManager, realFeeRate);
    const totalSats = optimalUtxos.reduce((s, u) => s + Math.round(u.amount * 1e8), 0);
    
    const dustThreshold = inputType === 'p2tr' ? 330 : 294;
    const vbytesWithChange = feeManager.estimateVBytes(inputType, optimalUtxos.length, 2);
    const vbytesNoChange = feeManager.estimateVBytes(inputType, optimalUtxos.length, 1);
    
    const feesWithChange = feeManager.calculateFeeForVsize(vbytesWithChange, realFeeRate);
    const feesNoChange = feeManager.calculateFeeForVsize(vbytesNoChange, realFeeRate);
    
    const netWithChange = totalSats - feesWithChange;
    const netNoChange = totalSats - feesNoChange;
    
    let maxSendable = 0;
    if (netWithChange > dustThreshold && netWithChange >= netNoChange) {
      maxSendable = netWithChange;
    } else if (netNoChange > 0) {
      maxSendable = netNoChange;
    }
    
    const finalMax = Math.max(0, (maxSendable / 1e8) - 0.00000001);
    
    console.log(`[MAX] Total usable: ${(totalSats / 1e8).toFixed(8)} NITO, UTXOs: ${optimalUtxos.length}, Max sendable: ${finalMax.toFixed(8)} NITO`);
    
    return finalMax;
    
  } catch (error) {
    console.error('[MAX] Calculation error:', error);
    return 0;
  }
}

// === MAIN TRANSACTION BUILDER ===
export class SimpleTransactionBuilder {
  constructor() {
    this.feeManager = new FeeManager();
  }

  async signTxWithPSBT(to, amt, isConsolidation = false, options = {}) {
    const { isMaxSend = false } = options;
    armInactivityTimerSafely();
    
    const walletInfo = await getWalletInfo();
    if (!walletInfo.isReady) {
      throw new Error('Import a wallet first.');
    }

    const selectedAddressType = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE)?.value || 'bech32';
    
    let sourceAddress;
    if (selectedAddressType === 'p2tr') {
      sourceAddress = walletInfo.addresses.taproot;
    } else {
      sourceAddress = walletInfo.addresses.bech32;
    }
    
    if (!sourceAddress) {
      throw new Error(`Source address not found for type: ${selectedAddressType}`);
    }
    
    if (!window.utxos) {
      throw new Error('Transaction functions unavailable');
    }

    const hdWallet = window.hdManager ? window.hdManager.hdWallet : null;
    const isHD = window.importType === 'hd';

    const rawUtxos = await window.utxos(sourceAddress, isHD, hdWallet);
    
    if (!rawUtxos.length) {
      throw new Error('No UTXOs available');
    }

    const matureUtxos = await filterMatureUtxos(rawUtxos);
    
    if (!matureUtxos.length) {
      throw new Error('No suitable mature UTXOs available');
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
      throw new Error(`No suitable ${selectedAddressType} mature UTXOs available`);
    }

    let filterContext = 'normal';
    if (isConsolidation) {
      filterContext = 'consolidation';
    } else if (isMaxSend) {
      filterContext = 'max';
    }

    const filtered = filterUtxosByContext(workingUtxos, filterContext);
    const availableUtxos = filtered.usableUtxos;

    if (!availableUtxos.length) {
      const errorMsg = isMaxSend 
        ? 'No UTXOs large enough for MAX transaction (all UTXOs are protected)'
        : 'No suitable UTXOs available for this transaction';
      throw new Error(errorMsg);
    }

    let selectedUtxos, total;
    const realFeeRate = await this.feeManager.getRealFeeRate();

    if (isConsolidation) {
      selectedUtxos = [...availableUtxos];
      total = selectedUtxos.reduce((s, u) => s + Math.round(u.amount * 1e8), 0);
    } else if (isMaxSend) {
      const inputType = selectedAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh';
      selectedUtxos = selectOptimalUtxosForMax(availableUtxos, inputType, this.feeManager, realFeeRate);
      total = selectedUtxos.reduce((s, u) => s + Math.round(u.amount * 1e8), 0);
      
      if (total <= 0) {
        throw new Error('Insufficient funds: no UTXOs available');
      }
    } else {
      selectedUtxos = [];
      total = 0;
      const target = Math.round(amt * 1e8);
      
      const sortedUtxos = [...availableUtxos].sort((a, b) => b.amount - a.amount);
      
      for (const u of sortedUtxos) {
        selectedUtxos.push(u);
        total += Math.round(u.amount * 1e8);
        
        const inputType = selectedAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh';
        const vbytes = this.feeManager.estimateVBytes(inputType, selectedUtxos.length, 2);
        const estimatedFees = this.feeManager.calculateFeeForVsize(vbytes, realFeeRate);
        
        if (total >= target + estimatedFees) {
          break;
        }
      }
      
      const finalInputType = selectedAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh';
      const finalVbytes = this.feeManager.estimateVBytes(finalInputType, selectedUtxos.length, 2);
      const finalFees = this.feeManager.calculateFeeForVsize(finalVbytes, realFeeRate);
      
      if (!isMaxSend && total < Math.round(amt * 1e8) + finalFees) {
        const shortfall = (Math.round(amt * 1e8) + finalFees - total) / 1e8;
        throw new Error(`Insufficient funds. Use the MAX button or reduce the amount by ${shortfall.toFixed(8)} NITO to cover fees.`);
      }
    }

    return await this.buildAndSignTransaction(to, Math.round(amt * 1e8), selectedUtxos, isConsolidation, selectedAddressType, isMaxSend);
  }

  async buildAndSignTransaction(to, target, selectedUtxos, isConsolidation, sourceAddressType, isMaxSend = false) {
    const { bitcoin } = await getBitcoinLibraries();
    
    const realFeeRate = await this.feeManager.getRealFeeRate();
    const inputType = sourceAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh';
    
    const total = selectedUtxos.reduce((s, u) => s + Math.round(u.amount * 1e8), 0);
    
    const vbytesWithChange = this.feeManager.estimateVBytes(inputType, selectedUtxos.length, 2);
    const vbytesNoChange = this.feeManager.estimateVBytes(inputType, selectedUtxos.length, 1);
    
    const feesWithChange = this.feeManager.calculateFeeForVsize(vbytesWithChange, realFeeRate);
    const feesNoChange = this.feeManager.calculateFeeForVsize(vbytesNoChange, realFeeRate);
    
    let actualTarget = target;
    let fees = feesWithChange;
    let useChange = true;
    
    if (isMaxSend && !isConsolidation) {
      const dustThreshold = sourceAddressType === 'p2tr' ? 330 : 294;
      const changeAmountWithChange = total - target - feesWithChange;
      const netWithChange = changeAmountWithChange > dustThreshold ? total - feesWithChange : 0;
      const netNoChange = total - feesNoChange;
      
      if (netWithChange >= netNoChange && netWithChange > 0) {
        actualTarget = netWithChange;
        fees = feesWithChange;
        useChange = true;
      } else if (netNoChange > 0) {
        actualTarget = netNoChange;
        fees = feesNoChange;
        useChange = false;
      } else {
        throw new Error('Insufficient funds: fees exceed total UTXO value');
      }
    } else if (isConsolidation) {
      actualTarget = total - feesNoChange;
      fees = feesNoChange;
      useChange = false;
    } else {
      const changeAmount = total - target - feesWithChange;
      const dustThreshold = sourceAddressType === 'p2tr' ? 330 : 294;
      
      if (changeAmount <= dustThreshold) {
        fees = feesNoChange;
        useChange = false;
      }
    }
    
    const change = total - actualTarget - fees;
    
    if (change < 0) {
      throw new Error('Insufficient funds after fee calculation');
    }

    const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
    psbt.setVersion(2);

    for (const utxo of selectedUtxos) {
      await this.addInputToPsbt(psbt, utxo, sourceAddressType);
    }

    psbt.addOutput({ address: to, value: actualTarget });

    if (useChange && change > 0) {
      const walletInfo = await getWalletInfo();
      const changeAddress = sourceAddressType === 'p2tr' ? walletInfo.addresses.taproot : walletInfo.addresses.bech32;
      psbt.addOutput({ address: changeAddress, value: change });
    }

    await this.signPsbtInputs(psbt, selectedUtxos, sourceAddressType);

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const hex = tx.toHex();
    
    return { 
      hex, 
      actualFees: fees / 1e8,
      actualAmount: actualTarget / 1e8,
      changeAmount: useChange ? change / 1e8 : 0
    };
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
        throw new Error('Missing tapInternalKey for taproot UTXO');
      }
      
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: { script: scriptBuffer, value },
        tapInternalKey: tapInternalKey
      });
    } else {
      throw new Error(`Unsupported script type: ${utxo.scriptType}`);
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
          throw new Error(`Missing keyPair for taproot UTXO ${i}`);
        }
        
        const tweaked = await TaprootUtils.tweakSigner(keyPair, { network: NITO_NETWORK });
        psbt.signInput(i, tweaked);
      } else {
        let keyPair = utxo.keyPair;
        
        if (!keyPair && window.getWalletKeyPair) {
          keyPair = await window.getWalletKeyPair();
        }
        
        if (!keyPair) {
          throw new Error(`Missing keyPair for ${utxo.scriptType} UTXO ${i}`);
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
    alert('Consolidation already in progress. Please wait.');
    return;
  }

  if (window.startOperation) window.startOperation('consolidation');
  armInactivityTimerSafely();
  console.log('[CONSOLIDATION] Starting consolidation...');

  try {
    const walletInfo = await getWalletInfo();
    if (!walletInfo.isReady) {
      alert('Import a wallet first.');
      return;
    }

    const sourceType = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE)?.value || 'bech32';

    const spinner = document.getElementById(ELEMENT_IDS.LOADING_SPINNER);
    if (spinner) spinner.style.display = 'block';

    if (!window.utxos) {
      throw new Error('Transaction functions unavailable');
    }

    const hdWallet = window.hdManager ? window.hdManager.hdWallet : null;
    const isHD = window.importType === 'hd';

    let rawUtxos = [];
    
    if (sourceType === 'p2tr') {
      const taprootAddress = walletInfo.addresses.taproot;
      
      if (!taprootAddress) {
        throw new Error('Taproot address not available');
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
      alert(`Need at least 2 mature UTXOs to consolidate. Found: ${allUtxos.length}`);
      return;
    }

    const totalValue = allUtxos.reduce((sum, u) => sum + u.amount, 0);

    const MAX_UTXOS_PER_BATCH = sourceType === 'p2tr' ? 1000 : 1500;
    const batches = [];
    
    for (let i = 0; i < allUtxos.length; i += MAX_UTXOS_PER_BATCH) {
      const batch = allUtxos.slice(i, i + MAX_UTXOS_PER_BATCH);
      batches.push(batch);
    }

    const confirmMsg = `Consolidate ${allUtxos.length} UTXOs → ${batches.length} UTXO(s)\nTotal: ${totalValue.toFixed(8)} NITO\nType: ${sourceType}\n\nConfirm?`;

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
          throw new Error('RPC function unavailable');
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

    alert(`Consolidation completed!\n${allUtxos.length} UTXOs → ${txids.length} UTXO(s)\nTransactions: ${txids.length}\nType: ${sourceType}`);
    
    console.log(`[CONSOLIDATION] Completed successfully: ${txids.length} transactions`);
    
    setTimeout(() => {
      const refreshBtn = document.getElementById(ELEMENT_IDS.REFRESH_BALANCE_BUTTON);
      if (refreshBtn) refreshBtn.click();
    }, 8000);

  } catch (e) {
    const spinner = document.getElementById(ELEMENT_IDS.LOADING_SPINNER);
    if (spinner) spinner.style.display = 'none';
    
    alert(`Consolidation error: ${e.message}`);
    console.error('[CONSOLIDATION] Error:', e);
  } finally {
    if (window.endOperation) window.endOperation('consolidation');
  }
}

// === TRANSFER TO P2SH ADDRESS ===
export async function transferToP2SH(amt) {
  armInactivityTimerSafely();
  
  if (!window.getWalletPublicKey) {
    throw new Error('Import a wallet first.');
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

// === EXPORTS ===
const transactionBuilder = new SimpleTransactionBuilder();

export async function signTx(to, amt, isConsolidation = false, options = {}) {
  return await transactionBuilder.signTxWithPSBT(to, amt, isConsolidation, options);
}

export async function signTxWithPSBT(to, amt, isConsolidation = false, options = {}) {
  return await transactionBuilder.signTxWithPSBT(to, amt, isConsolidation, options);
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
  window.UTXO_PROTECTION = UTXO_PROTECTION;
  window.filterUtxosByContext = filterUtxosByContext;
  window.calculateMaxSendableAmount = calculateMaxSendableAmount;
  window.signTx = signTx;
  window.signTxWithPSBT = signTxWithPSBT;
  window.signTxBatch = signTxBatch;
  window.transferToP2SH = transferToP2SH;
  window.consolidateUtxos = consolidateUtxos;
  window.feeForVsize = feeForVsize;
  window.effectiveFeeRate = effectiveFeeRate;
}

console.log('Transactions module loaded - Version 2.0.0');