// Transaction Management for NITO Wallet
// Handles transaction creation, signing, and UTXO consolidation

import { NITO_NETWORK, TRANSACTION_CONFIG, ELEMENT_IDS } from './config.js';
import { armInactivityTimerSafely } from './security.js';
import { eventBus, EVENTS } from './events.js';
import { waitForLibraries } from './vendor.js';

// === TRANSLATION HELPER ===
function getTranslation(key, fallback, params = {}) {
  const t = (window.i18next && typeof window.i18next.t === 'function') 
    ? window.i18next.t 
    : () => fallback || key;
  return t(key, { ...params, defaultValue: fallback });
}

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

async function getWalletInfo() {
  return new Promise((resolve) => {
    eventBus.once(EVENTS.WALLET_INFO_RESPONSE, resolve, { timeout: 3000 });
    eventBus.emit(EVENTS.WALLET_INFO_REQUEST);
  }).catch(() => {
    return { address: '', isReady: false, addresses: {} };
  });
}

let lastTxid = null;

if (typeof window !== 'undefined') {
  window._lastConsolidationTxid = null;
}

// Fee calculation and estimation
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
      return this.minFeeRate;
    }
  }

  calculateFeeForVsize(vbytes, feeRate) {
    return Math.ceil(vbytes * (feeRate * 1e8) / 1000);
  }

  estimateVBytes(inputType, numInputs) {
    const inputSizes = { p2pkh: 148, p2wpkh: 68, p2sh: 91, p2tr: 57.5 };
    const outputSize = 31;
    const overhead = 10;
    
    const inputSize = inputSizes[inputType] || inputSizes.p2wpkh;
    return overhead + (inputSize * numInputs) + outputSize;
  }
}

// Taproot utilities for key tweaking
export class TaprootUtils {
  static toXOnly(pubkey) {
    if (!pubkey || pubkey.length < 33) {
      throw new Error('Invalid public key for X-only conversion');
    }
    return Buffer.from(pubkey.slice(1, 33));
  }

  static async tweakSigner(signer, opts = {}) {
    const { bitcoin } = await getBitcoinLibraries();
    
    if (!bitcoin.crypto) {
      throw new Error('Bitcoin crypto functions not available');
    }

    let privateKey = Buffer.from(signer.privateKey);
    const publicKey = Buffer.from(signer.publicKey);
    
    if (publicKey[0] === 3) {
      privateKey = bitcoin.crypto.privateNegate(privateKey);
    }
    
    const tweakHash = opts.tweakHash ? Buffer.from(opts.tweakHash) : Buffer.alloc(0);
    const tapTweakHash = bitcoin.crypto.taggedHash('TapTweak', Buffer.concat([TaprootUtils.toXOnly(signer.publicKey), tweakHash]));
    const tweak = Buffer.from(tapTweakHash);
    const tweakedPrivateKey = bitcoin.crypto.privateAdd(privateKey, tweak);
    
    if (!tweakedPrivateKey) {
      const errorMsg = getTranslation('security.invalid_tweaked_key', 'Clé privée modifiée invalide');
      throw new Error(errorMsg);
    }
    
    const tweakedPublicKey = bitcoin.crypto.pointFromScalar(tweakedPrivateKey, true);
    
    return {
      publicKey: Buffer.from(tweakedPublicKey),
      signSchnorr: (hash) => {
        const randomBytes = crypto.getRandomValues(new Uint8Array(32));
        return bitcoin.crypto.signSchnorr(hash, tweakedPrivateKey, Buffer.from(randomBytes));
      }
    };
  }
}

// Filter mature UTXOs (coinbase and confirmation checks)
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

// Main transaction builder class
export class SimpleTransactionBuilder {
  constructor() {
    this.feeManager = new FeeManager();
  }

  async signTxWithPSBT(to, amt, isConsolidation = false) {
    armInactivityTimerSafely();
    
    const walletInfo = await getWalletInfo();
    if (!walletInfo.isReady) {
      const errorMsg = getTranslation('errors.import_first', 'Importez d\'abord un wallet.');
      throw new Error(errorMsg);
    }

    const selectedAddressType = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE)?.value || 'bech32';
    const sourceAddress = selectedAddressType === 'p2tr' ? walletInfo.addresses.taproot : walletInfo.addresses.bech32;
    
    if (!window.utxos) {
      const errorMsg = getTranslation('errors.transaction_functions_unavailable', 'Fonctions de transaction non disponibles');
      throw new Error(errorMsg);
    }

    const hdWallet = window.hdManager ? window.hdManager.hdWallet : null;
    const isHD = window.importType === 'hd';

    const rawUtxos = await window.utxos(sourceAddress, isHD, hdWallet);
    if (!rawUtxos.length) {
      const errorMsg = getTranslation('transactions.no_utxos_for_consolidation', 'Aucun UTXO disponible pour la consolidation');
      throw new Error(errorMsg);
    }

    const matureUtxos = await filterMatureUtxos(rawUtxos);
    if (!matureUtxos.length) {
      const errorMsg = getTranslation('transactions.no_suitable_utxos', 'Aucun UTXO mature approprié disponible');
      throw new Error(errorMsg);
    }

    let workingUtxos;
    if (isConsolidation) {
      workingUtxos = selectedAddressType === 'p2tr' 
        ? matureUtxos.filter(u => u.scriptType === 'p2tr')
        : matureUtxos.filter(u => ['p2wpkh', 'p2pkh', 'p2sh'].includes(u.scriptType));
    } else {
      const filteredUtxos = window.filterOpReturnUtxos ? await window.filterOpReturnUtxos(matureUtxos) : matureUtxos;
      workingUtxos = selectedAddressType === 'p2tr' 
        ? filteredUtxos.filter(u => u.scriptType === 'p2tr')
        : filteredUtxos.filter(u => ['p2wpkh', 'p2pkh', 'p2sh'].includes(u.scriptType));
    }

    if (!workingUtxos.length) {
      const errorMsg = getTranslation('transactions.no_suitable_utxos', 'Aucun UTXO mature approprié disponible');
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
        
        const vbytes = this.feeManager.estimateVBytes(selectedAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh', selectedUtxos.length);
        const estimatedFees = this.feeManager.calculateFeeForVsize(vbytes, realFeeRate);
        
        if (total >= target + estimatedFees) {
          break;
        }
      }
      
      const finalVbytes = this.feeManager.estimateVBytes(selectedAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh', selectedUtxos.length);
      const finalFees = this.feeManager.calculateFeeForVsize(finalVbytes, realFeeRate);
      
      if (total < target + finalFees) {
        const shortfall = (target + finalFees - total) / 1e8;
        const errorMsg = getTranslation('transactions.insufficient_funds_detailed', 
          `Fonds insuffisants. Utilisez le bouton MAX ou réduisez le montant de ${shortfall.toFixed(8)} NITO pour couvrir les frais.`,
          { amount: shortfall.toFixed(8) }
        );
        throw new Error(errorMsg);
      }
    }

    return this.buildAndSignTransaction(to, target, selectedUtxos, isConsolidation, selectedAddressType);
  }

  async buildAndSignTransaction(to, target, selectedUtxos, isConsolidation, sourceAddressType) {
    const { bitcoin } = await getBitcoinLibraries();
    
    const realFeeRate = await this.feeManager.getRealFeeRate();
    const vbytes = this.feeManager.estimateVBytes(sourceAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh', selectedUtxos.length);
    const fees = this.feeManager.calculateFeeForVsize(vbytes, realFeeRate);
    
    const total = selectedUtxos.reduce((s, u) => s + Math.round(u.amount * 1e8), 0);
    const change = total - target - fees;
    
    if (change < 0) {
      const errorMsg = getTranslation('transactions.insufficient_funds_after_fees', 'Fonds insuffisants après calcul des frais');
      throw new Error(errorMsg);
    }

    const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
    psbt.setVersion(2);

    for (const utxo of selectedUtxos) {
      await this.addInputToPsbt(psbt, utxo);
    }

    psbt.addOutput({ address: to, value: target });

    const dustThreshold = sourceAddressType === 'p2tr' ? 330 : 294;
    if (change > dustThreshold && !isConsolidation) {
      const walletInfo = await getWalletInfo();
      const changeAddress = sourceAddressType === 'p2tr' ? walletInfo.addresses.taproot : walletInfo.addresses.bech32;
      psbt.addOutput({ address: changeAddress, value: change });
    }

    await this.signPsbtInputs(psbt, selectedUtxos);

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const hex = tx.toHex();

    return { hex, actualFees: fees / 1e8 };
  }

  async addInputToPsbt(psbt, utxo) {
    const scriptBuffer = Buffer.from(utxo.scriptPubKey, 'hex');
    
    if (utxo.scriptType === 'p2wpkh') {
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: { script: scriptBuffer, value: Math.round(utxo.amount * 1e8) }
      });
    } else if (utxo.scriptType === 'p2sh') {
      const redeem = utxo.redeemScript;
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: { script: scriptBuffer, value: Math.round(utxo.amount * 1e8) },
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
      const tapInternalKey = utxo.tapInternalKey;
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: { script: scriptBuffer, value: Math.round(utxo.amount * 1e8) },
        tapInternalKey: tapInternalKey
      });
    }
  }

  async signPsbtInputs(psbt, selectedUtxos) {
    for (let i = 0; i < selectedUtxos.length; i++) {
      const u = selectedUtxos[i];
      
      if (u.scriptType === 'p2tr') {
        const kp = u.keyPair;
        if (!kp) {
          throw new Error('Taproot key pair not available in UTXO');
        }
        const tweaked = await TaprootUtils.tweakSigner(kp, { network: NITO_NETWORK });
        psbt.signInput(i, tweaked);
      } else {
        const kp = u.keyPair;
        if (!kp) {
          throw new Error(`Key pair not available in UTXO for ${u.scriptType}`);
        }
        
        const signer = {
          network: kp.network,
          privateKey: Buffer.from(kp.privateKey),
          publicKey: Buffer.from(kp.publicKey),
          sign: (hash) => Buffer.from(kp.sign(hash))
        };
        
        psbt.signInput(i, signer);
      }
    }
  }
}

// Consolidate UTXOs with proper address type handling
export async function consolidateUtxos() {
  armInactivityTimerSafely();
  console.log('Starting consolidation...');

  try {
    const walletInfo = await getWalletInfo();
    if (!walletInfo.isReady) {
      const alertMsg = getTranslation('errors.import_first', 'Importez d\'abord un wallet.');
      alert(alertMsg);
      return;
    }

    const sourceType = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE)?.value || 'bech32';

    const spinner = document.getElementById(ELEMENT_IDS.LOADING_SPINNER);
    if (spinner) spinner.style.display = 'block';

    if (!window.utxos) {
      const errorMsg = getTranslation('errors.transaction_functions_unavailable', 'Fonctions de transaction non disponibles');
      throw new Error(errorMsg);
    }

    const hdWallet = window.hdManager ? window.hdManager.hdWallet : null;
    const isHD = window.importType === 'hd';

    let rawUtxos = [];
    
    if (sourceType === 'p2tr') {
      const taprootAddress = walletInfo.addresses.taproot;
      rawUtxos = await window.utxos(taprootAddress, isHD, hdWallet);
      rawUtxos = rawUtxos.filter(u => u.scriptType === 'p2tr');
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
      const alertMsg = getTranslation('transactions.need_at_least_utxos',
        `Besoin d'au moins 2 UTXOs matures pour consolider. Trouvés: ${allUtxos.length}`,
        { count: 2, found: allUtxos.length }
      );
      alert(alertMsg);
      return;
    }

    const totalValue = allUtxos.reduce((sum, u) => sum + u.amount, 0);

    const MAX_UTXOS_PER_BATCH = 1500;
    const batches = [];
    
    for (let i = 0; i < allUtxos.length; i += MAX_UTXOS_PER_BATCH) {
      const batch = allUtxos.slice(i, i + MAX_UTXOS_PER_BATCH);
      batches.push(batch);
    }

    const confirmMsg = getTranslation('transactions.consolidation_confirm',
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
      const vbytes = transactionBuilder.feeManager.estimateVBytes(
        sourceType === 'p2tr' ? 'p2tr' : 'p2wpkh', 
        batch.length
      );
      const estimatedFee = transactionBuilder.feeManager.calculateFeeForVsize(vbytes, realFeeRate) / 1e8;
      const netAmount = batchTotal - estimatedFee;

      if (netAmount <= 0) {
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
          const errorMsg = getTranslation('errors.rpc_unavailable', 'Fonction RPC non disponible');
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
        throw error;
      }
    }

    if (spinner) spinner.style.display = 'none';

    const finalTxid = txids[txids.length - 1];
    if (finalTxid && window.showSuccessPopup) {
      await window.showSuccessPopup(finalTxid);
    }

    const successMsg = getTranslation('transactions.consolidation_completed',
      `Consolidation terminée!\n${allUtxos.length} UTXOs → ${txids.length} UTXO(s)\nTransactions: ${txids.length}\nType: ${sourceType}`,
      { 
        original: allUtxos.length, 
        final: txids.length, 
        txCount: txids.length, 
        type: sourceType 
      }
    );

    alert(successMsg);
    
    setTimeout(() => {
      const refreshBtn = document.getElementById(ELEMENT_IDS.REFRESH_BALANCE_BUTTON);
      if (refreshBtn) refreshBtn.click();
    }, 2000);

  } catch (e) {
    const spinner = document.getElementById(ELEMENT_IDS.LOADING_SPINNER);
    if (spinner) spinner.style.display = 'none';
    
    const errorMsg = getTranslation('transactions.consolidation_error', 
      `Erreur de consolidation: ${e.message}`,
      { error: e.message }
    );
    alert(errorMsg);
    console.error('Consolidation error:', e);
  }
}

// Transfer to P2SH address
export async function transferToP2SH(amt) {
  armInactivityTimerSafely();
  
  if (!window.getWalletPublicKey) {
    const errorMsg = getTranslation('errors.import_first', 'Importez d\'abord un wallet.');
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

console.log('Transactions module loaded with UTXO key-pair signing');
