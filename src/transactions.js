import { TRANSACTION_CONFIG, VALIDATION_PATTERNS, NITO_NETWORK, UTXO_VALUES, getTranslation, sleep } from './config.js';
import { eventBus, EVENTS } from './events.js';
import { armInactivityTimerSafely } from './security.js';
import { getBitcoinLibraries } from './vendor.js';
import {
  rpcClient,
  utxos,
  balance,
  filterMatureUtxos,
  AddressManager,
  TaprootUtils,
  handleError500WithRetry,
  waitForConfirmation
} from './blockchain.js';
import { showInfoPopup, showConsolidationConfirmPopup, showSuccessPopup, showSimpleProgressBar } from './ui-popups.js';

// === UTXO FILTERING BY CONTEXT ===
function filterUtxosByContext(utxos, context = 'normal') {
  const usableUtxos = [];
  const protectedUtxos = [];

  for (const utxo of utxos) {
    const amount = typeof utxo.amount === 'number' ? utxo.amount : parseFloat(utxo.amount) || 0;
    const amountSats = Math.round(amount * 1e8);

    if (context === 'consolidation') {
      usableUtxos.push(utxo);
    } else {
      if (amountSats >= UTXO_VALUES.MIN_TRANSACTION) {
        usableUtxos.push(utxo);
      } else {
        protectedUtxos.push(utxo);
      }
    }
  }

  return { usableUtxos, protectedUtxos };
}

// === FILTER UTXOS BY MINIMUM VALUE ===
export function filterUtxosByMinValue(utxos, minValue, scriptType = null) {
  if (!Array.isArray(utxos)) return [];

  return utxos.filter(utxo => {
    if (!utxo || typeof utxo.amount !== 'number') return false;

    if (scriptType && utxo.scriptType !== scriptType) return false;

    const amountSats = Math.round(utxo.amount * 1e8);
    const minSats = Math.round(minValue);

    return amountSats >= minSats;
  });
}

// === FEE MANAGER ===
export class FeeManager {
  constructor() {
    this.minFeeRate = TRANSACTION_CONFIG.MIN_FEE_RATE;
    this.lastFeeRate = null;
    this.lastFeeTime = 0;
    this.cacheDuration = 30000;
  }

  async getRealFeeRate() {
    const now = Date.now();

    if (this.lastFeeRate && (now - this.lastFeeTime) < this.cacheDuration) {
      return this.lastFeeRate;
    }

    let estimatedRate = this.minFeeRate;

    try {
      const [feeInfo, mempoolInfo] = await Promise.allSettled([
        rpcClient.call('estimatesmartfee', [6]),
        rpcClient.call('getmempoolinfo')
      ]);

      if (feeInfo.status === 'fulfilled' && feeInfo.value && feeInfo.value.feerate) {
        estimatedRate = Math.max(feeInfo.value.feerate, this.minFeeRate);
      } else if (mempoolInfo.status === 'fulfilled' && mempoolInfo.value) {
        const mempool = mempoolInfo.value;
        const size = mempool.size || 0;
        const bytes = mempool.bytes || 0;

        if (size > 1000) {
          const avgFeePerTx = bytes > 0 ? (mempool.total_fee || 0) / size : 0;
          if (avgFeePerTx > 0) {
            const avgSize = bytes / size;
            estimatedRate = Math.max((avgFeePerTx / avgSize) * 1000, this.minFeeRate);
          }
        }
      }

      const dynamicRate = TRANSACTION_CONFIG.DYNAMIC_FEE_RATE || this.minFeeRate;
      estimatedRate = Math.max(estimatedRate, dynamicRate);

      this.lastFeeRate = estimatedRate;
      this.lastFeeTime = now;

      console.log(`[FEE] Rate: ${estimatedRate} BTC/kB (${this.btcPerKbToSatPerVb(estimatedRate)} sat/vB)`);

      return estimatedRate;

    } catch (e) {
      console.warn(`[FEE] ${getTranslation('ui.refresh_error', 'Refresh error: {{error}}', {error: e.message})}`);
      const safeFallback = 0.00001;
      this.lastFeeRate = safeFallback;
      this.lastFeeTime = now;
      return safeFallback;
    }
  }

  btcPerKbToSatPerVb(btcPerKb) {
    return Math.round((btcPerKb * 1e8) / 1000);
  }

  estimateVBytes(inputType, numInputs, numOutputs) {
    const INPUT_SIZES = {
      'p2pkh': 148,
      'p2wpkh': 68,
      'p2sh': 91,
      'p2tr': 58
    };

    const OUTPUT_SIZE = 34;
    const OVERHEAD = 10;

    const inputSize = INPUT_SIZES[inputType] || INPUT_SIZES['p2wpkh'];
    const totalInputSize = numInputs * inputSize;
    const totalOutputSize = numOutputs * OUTPUT_SIZE;

    return OVERHEAD + totalInputSize + totalOutputSize;
  }

  calculateFeeForVsize(vbytes, feeRateBtcPerKb) {
    const satPerVb = this.btcPerKbToSatPerVb(feeRateBtcPerKb);
    const feeSats = Math.ceil(vbytes * satPerVb);
    return feeSats;
  }

  calculateMessageChunkAmount(feeRate) {
    const vbytes = this.estimateVBytes('p2wpkh', 1, 3);
    const fee = this.calculateFeeForVsize(vbytes, feeRate);
    const messageUtxoValue = 294;
    const chunkAmount = fee + messageUtxoValue;
    return Math.ceil(chunkAmount * TRANSACTION_CONFIG.CHUNK_AMOUNT_MULTIPLIER);
  }
}

// === TRANSACTION BUILDER ===
export class TransactionBuilder {
  constructor() {
    this.feeManager = new FeeManager();
  }

  async buildAndSignTransaction(destinationAddress, amountSats, selectedUtxos, isConsolidation = false, sourceType = 'bech32', isMaxSend = false) {
    const { bitcoin } = await getBitcoinLibraries();
    const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
    psbt.setVersion(2);

    let totalInput = 0;
    const inputDetails = [];

    for (let i = 0; i < selectedUtxos.length; i++) {
      const utxo = selectedUtxos[i];
      const inputValue = Math.round(utxo.amount * 1e8);
      totalInput += inputValue;

      const scriptBuffer = Buffer.from(utxo.scriptPubKey, 'hex');
      const scriptType = utxo.scriptType || 'p2wpkh';

      if (scriptType === 'p2tr') {
        const enrichedUtxo = await TaprootUtils.prepareTaprootUtxo(utxo);

        psbt.addInput({
          hash: enrichedUtxo.txid,
          index: enrichedUtxo.vout,
          witnessUtxo: { script: scriptBuffer, value: inputValue },
          tapInternalKey: enrichedUtxo.tapInternalKey
        });

        inputDetails.push({
          index: i,
          type: 'p2tr',
          keyPair: enrichedUtxo.keyPair,
          tapInternalKey: enrichedUtxo.tapInternalKey
        });
      } else if (scriptType === 'p2pkh') {
        const rawTx = await window.rpc('getrawtransaction', [utxo.txid]);
        const txBuffer = Buffer.from(rawTx, 'hex');

        psbt.addInput({
          hash: utxo.txid,
          index: utxo.vout,
          nonWitnessUtxo: txBuffer
        });

        const keyPair = await this.getKeyPairForUtxo(utxo, scriptType);
        inputDetails.push({
          index: i,
          type: scriptType,
          keyPair,
          utxo
        });
      } else if (scriptType === 'p2sh') {
        const publicKey = await this.getPublicKeyForUtxo(utxo, scriptType);
        const p2wpkh = bitcoin.payments.p2wpkh({
          pubkey: Buffer.from(publicKey),
          network: NITO_NETWORK
        });
        const p2sh = bitcoin.payments.p2sh({
          redeem: p2wpkh,
          network: NITO_NETWORK
        });

        psbt.addInput({
          hash: utxo.txid,
          index: utxo.vout,
          witnessUtxo: { script: scriptBuffer, value: inputValue },
          redeemScript: p2sh.redeem.output
        });

        const keyPair = await this.getKeyPairForUtxo(utxo, scriptType);
        inputDetails.push({
          index: i,
          type: scriptType,
          keyPair,
          utxo
        });
      } else {
        psbt.addInput({
          hash: utxo.txid,
          index: utxo.vout,
          witnessUtxo: { script: scriptBuffer, value: inputValue }
        });

        const keyPair = await this.getKeyPairForUtxo(utxo, sourceType);
        inputDetails.push({
          index: i,
          type: scriptType,
          keyPair
        });
      }
    }

    const realFeeRate = await this.feeManager.getRealFeeRate();
    const inputType = sourceType === 'p2tr' ? 'p2tr' : 'p2wpkh';

    let estimatedFee;
    let change;

    if (isConsolidation || isMaxSend) {
      const vbytes = this.feeManager.estimateVBytes(inputType, selectedUtxos.length, 1);
      estimatedFee = this.feeManager.calculateFeeForVsize(vbytes, realFeeRate);

      const finalAmount = totalInput - estimatedFee;

      if (finalAmount <= 546) {
        throw new Error(getTranslation('transactions.insufficient_funds_after_fees', 'Insufficient funds after fees'));
      }

      psbt.addOutput({
        address: destinationAddress,
        value: finalAmount
      });

      change = 0;
    } else {
      const vbytes = this.feeManager.estimateVBytes(inputType, selectedUtxos.length, 2);
      estimatedFee = this.feeManager.calculateFeeForVsize(vbytes, realFeeRate);

      change = totalInput - amountSats - estimatedFee;

      if (change < 0) {
        throw new Error(getTranslation('transactions.insufficient_funds_after_fees', 'Insufficient funds after fees'));
      }

      psbt.addOutput({
        address: destinationAddress,
        value: amountSats
      });

      let changeAddress;
      if (sourceType === 'p2tr') {
        changeAddress = window.taprootAddress || window.bech32Address;
      } else {
        changeAddress = window.bech32Address;
      }
      
      if (!changeAddress) {
        throw new Error('No change address available');
      }

      if (change > 546) {
        psbt.addOutput({
          address: changeAddress,
          value: change
        });
      } else if (change > 0) {
        console.log(`[TX] Dust change of ${change} sats added to fee`);
      }
    }

    try {
      for (let i = 0; i < inputDetails.length; i++) {
        const detail = inputDetails[i];

        if (detail.type === 'p2tr') {
          const tweakedSigner = TaprootUtils.tweakSigner(detail.keyPair);
          psbt.signInput(i, tweakedSigner);
          
          if (tweakedSigner.privateKey) tweakedSigner.privateKey.fill(0);
          if (detail.keyPair.privateKey) detail.keyPair.privateKey.fill(0);
        } else if (detail.type === 'p2pkh') {
          const publicKeyBuffer = Buffer.from(detail.keyPair.publicKey);
          const signer = {
            network: detail.keyPair.network,
            publicKey: publicKeyBuffer,
            sign: (hash) => Buffer.from(detail.keyPair.sign(hash))
          };
          psbt.signInput(i, signer);
          
          if (detail.keyPair.privateKey) detail.keyPair.privateKey.fill(0);
        } else if (detail.type === 'p2sh') {
          const publicKeyBuffer = Buffer.from(await this.getPublicKeyForUtxo(detail.utxo, detail.type));
          const signer = {
            network: detail.keyPair.network,
            privateKey: Buffer.from(detail.keyPair.privateKey),
            publicKey: publicKeyBuffer,
            sign: (hash) => Buffer.from(detail.keyPair.sign(hash))
          };
          psbt.signInput(i, signer);
          
          if (signer.privateKey) signer.privateKey.fill(0);
          if (detail.keyPair.privateKey) detail.keyPair.privateKey.fill(0);
        } else {
          const publicKeyBuffer = Buffer.from(await this.getPublicKeyForUtxo(selectedUtxos[i], sourceType));
          const signer = {
            network: detail.keyPair.network,
            privateKey: Buffer.from(detail.keyPair.privateKey),
            publicKey: publicKeyBuffer,
            sign: (hash) => Buffer.from(detail.keyPair.sign(hash))
          };
          psbt.signInput(i, signer);
          
          if (signer.privateKey) signer.privateKey.fill(0);
          if (detail.keyPair.privateKey) detail.keyPair.privateKey.fill(0);
        }
      }

      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      const txHex = tx.toHex();
      const txid = tx.getId();

      console.log(`[TX] Built: ${txid.substring(0,8)}... | Fee: ${estimatedFee} sats | Inputs: ${selectedUtxos.length} | Change: ${change}`);

      return {
        hex: txHex,
        txid,
        vbytes: tx.virtualSize(),
        fee: estimatedFee,
        feeRate: realFeeRate
      };

    } finally {
      inputDetails.forEach(detail => {
        if (detail.keyPair?.privateKey) {
          try {
            if (Buffer.isBuffer(detail.keyPair.privateKey)) {
              detail.keyPair.privateKey.fill(0);
            } else if (detail.keyPair.privateKey instanceof Uint8Array) {
              detail.keyPair.privateKey.fill(0);
            }
          } catch (e) {}
        }
      });
    }
  }

  async getKeyPairForUtxo(utxo, scriptType) {
    if (window.importType === 'hd' && window.hdManager) {
      const pathMap = {
        'p2pkh': "m/44'/0'/0'",
        'p2sh': "m/49'/0'/0'",
        'p2wpkh': "m/84'/0'/0'",
        'p2tr': "m/86'/0'/0'"
      };
      
      const path = pathMap[utxo.scriptType];
      
      if (path) {
        return await window.hdManager.getKeyPairByPath(path);
      } else {
        return await window.hdManager.getKeyPair();
      }
    } else {
      if (scriptType === 'p2tr') {
        return await window.getTaprootKeyPair();
      } else {
        return await window.getWalletKeyPair();
      }
    }
  }

  async getPublicKeyForUtxo(utxo, scriptType) {
    if (window.importType === 'hd' && window.hdManager) {
      if (scriptType === 'p2tr') {
        return await window.hdManager.getTaprootPublicKey();
      } else {
        return await window.hdManager.getPublicKey();
      }
    } else {
      if (scriptType === 'p2tr') {
        return await window.getTaprootPublicKey();
      } else {
        return await window.getWalletPublicKey();
      }
    }
  }
}

// === CALCULATE MAX SENDABLE AMOUNT ===
export async function calculateMaxSendableAmount() {
  try {
    if (!window.rpc) {
      throw new Error(getTranslation('transactions.rpc_function_unavailable', 'RPC function unavailable'));
    }

    const isHD = window.importType === 'hd';
    const hdWallet = isHD && window.hdManager ? window.hdManager.hdWallet : null;

    const selectedType = document.getElementById('debitAddressType')?.value || 'bech32';
    const sourceType = selectedType === 'p2tr' ? 'p2tr' : 'bech32';

    let sourceAddress = '';
    if (sourceType === 'p2tr') {
      sourceAddress = window.taprootAddress || '';
    } else {
      sourceAddress = window.bech32Address || '';
    }

    if (!sourceAddress) {
      throw new Error(getTranslation('transactions.source_address_not_found', 'Source address not found for type: {{type}}', { type: sourceType }));
    }

    console.log(`[MAX] Calculating for ${sourceType}, address: ${sourceAddress.substring(0, 15)}...`);

    const allUtxos = await utxos(sourceAddress, isHD, hdWallet);

    if (!allUtxos || allUtxos.length === 0) {
      console.log('[MAX] No UTXOs found');
      return 0;
    }

    console.log(`[MAX] Total UTXOs retrieved: ${allUtxos.length}`);

    const workingUtxos = allUtxos.filter(u => u && typeof u.amount === 'number' && u.amount > 0);

    if (!workingUtxos.length) {
      return 0;
    }

    const filtered = filterUtxosByContext(workingUtxos, 'max');

    if (!filtered.usableUtxos.length) {
      if (workingUtxos.length > 1) {
        console.log(`[MAX] ${getTranslation('transactions.need_at_least_utxos', 'Need at least {{count}} mature UTXOs to consolidate', {count: 2})}`);
      }
      return 0;
    }

    const sortedUtxos = filtered.usableUtxos.sort((a, b) => b.amount - a.amount);

    const feeManager = new FeeManager();
    const feeRate = await feeManager.getRealFeeRate();

    const inputType = sourceType === 'p2tr' ? 'p2tr' : 'p2wpkh';

    let maxAmount = 0;
    let bestUtxoCount = 0;

    for (let numUtxos = 1; numUtxos <= Math.min(sortedUtxos.length, 50); numUtxos++) {
      const selectedUtxos = sortedUtxos.slice(0, numUtxos);
      const totalInput = selectedUtxos.reduce((sum, u) => sum + u.amount, 0);

      const vbytes = feeManager.estimateVBytes(inputType, numUtxos, 1);
      const estimatedFee = feeManager.calculateFeeForVsize(vbytes, feeRate) / 1e8;

      const netAmount = totalInput - estimatedFee;

      if (netAmount > maxAmount) {
        maxAmount = netAmount;
        bestUtxoCount = numUtxos;
      }
    }

    console.log(`[MAX] Best configuration: ${bestUtxoCount} UTXOs → ${maxAmount.toFixed(8)} NITO`);

    return Math.max(0, maxAmount);

  } catch (error) {
    console.error(`[MAX] ${getTranslation('ui.max_calculation_error', 'MAX calculation error: {{error}}', {error: error.message})}`);
    return 0;
  }
}

// === BROADCAST WITH RETRY ===
export async function broadcastWithRetry(txHex, maxRetries = 3) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const txid = await window.rpc('sendrawtransaction', [txHex]);
      return txid;
    } catch (error) {
      const errorMsg = String(error.message || error);

      if (errorMsg.includes('already in block chain') || errorMsg.includes('txn-already-known')) {
        const txidMatch = txHex.match(/[a-f0-9]{64}/);
        if (txidMatch) return txidMatch[0];
        throw error;
      }

      if (attempt === maxRetries - 1) {
        throw error;
      }

      await sleep(1000 * (attempt + 1));
    }
  }
}

// === CONSOLIDATE UTXOS ===
export async function consolidateUTXOs() {
  armInactivityTimerSafely();

  try {
    if (window.isOperationActive && window.isOperationActive('consolidation')) {
      await showInfoPopup(getTranslation('transactions.consolidation_in_progress', 'Consolidation already in progress. Please wait.'));
      return;
    }

    if (window.startOperation) window.startOperation('consolidation');

    const isHD = window.importType === 'hd';
    const hdWallet = isHD && window.hdManager ? window.hdManager.hdWallet : null;

    const selectedType = document.getElementById('debitAddressType')?.value || 'bech32';
    const sourceType = selectedType === 'p2tr' ? 'p2tr' : 'bech32';

    let sourceAddress = '';
    let destinationAddress = '';

    if (sourceType === 'p2tr') {
      sourceAddress = window.taprootAddress || '';
      destinationAddress = window.taprootAddress || '';
    } else {
      sourceAddress = window.bech32Address || '';
      destinationAddress = window.bech32Address || '';
    }

    if (!sourceAddress || !destinationAddress) {
      throw new Error(getTranslation('transactions.source_address_not_found', 'Source address not found for type: {{type}}', { type: sourceType }));
    }

    console.log(`[CONSOLIDATION] Starting for ${sourceType}, address: ${sourceAddress.substring(0, 15)}...`);

    const allUtxos = await utxos(sourceAddress, isHD, hdWallet);

    if (!allUtxos || allUtxos.length === 0) {
      await showInfoPopup(getTranslation('transactions.no_utxos_for_consolidation', 'No UTXOs available for consolidation'));
      return;
    }

    console.log(`[CONSOLIDATION] Found ${allUtxos.length} UTXOs (types: ${[...new Set(allUtxos.map(u => u.scriptType))].join(', ')})`);

    const workingUtxos = allUtxos.filter(u => u && typeof u.amount === 'number' && u.amount > 0);

    const { usableUtxos } = filterUtxosByContext(workingUtxos, 'consolidation');

    if (usableUtxos.length < 2) {
      await showInfoPopup(getTranslation('transactions.need_at_least_two_utxos', 'Need at least 2 mature UTXOs to consolidate. Found: {{found}}', { found: usableUtxos.length }));
      return;
    }

    const totalAmount = usableUtxos.reduce((sum, u) => sum + u.amount, 0);
    const utxosPerBatch = TRANSACTION_CONFIG.MAX_UTXOS_PER_BATCH;
    const numBatches = Math.ceil(usableUtxos.length / utxosPerBatch);

    const confirmed = await showConsolidationConfirmPopup(usableUtxos.length, numBatches);

    if (!confirmed) {
      return;
    }

    const batches = [];
    for (let i = 0; i < usableUtxos.length; i += utxosPerBatch) {
      batches.push(usableUtxos.slice(i, i + utxosPerBatch));
    }

    const transactionBuilder = new TransactionBuilder();

    const txids = [];
    let lastTxid = null;

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];

      const matureBatch = await filterMatureUtxos(batch);

      if (matureBatch.length === 0) {
        console.warn(`[CONSOLIDATION] ${getTranslation('transactions.consolidation_batch_skipped', 'Consolidation batch {{batch}} skipped', {batch: i + 1})}`);
        continue;
      }

      const finalBatchTotal = matureBatch.reduce((sum, u) => sum + u.amount, 0);
      console.log(`[CONSOLIDATION] Batch ${i + 1}: ${matureBatch.length} UTXOs, total: ${finalBatchTotal.toFixed(8)} NITO`);

      try {
        const result = await transactionBuilder.buildAndSignTransaction(
          destinationAddress,
          0,
          matureBatch,
          true,
          sourceType
        );

        const txid = await window.rpc('sendrawtransaction', [result.hex]);
        txids.push(txid);
        console.log(`[CONSOLIDATION] Batch ${i + 1}/${batches.length} completed: ${txid.substring(0, 8)}... (Fee: ${result.fee} sats)`);

        const batchPercentage = Math.round(((i + 1) / batches.length) * 100);
        if (window.showSimpleProgressBar) {
          window.showSimpleProgressBar(batchPercentage);
        }

        if (i === batches.length - 1) {
          lastTxid = txid;
        }

        if (window.CacheManager) {
          window.CacheManager.invalidateAddress(destinationAddress, isHD);
        }

      } catch (error) {
        console.error(`[CONSOLIDATION] ${getTranslation('transactions.consolidation_batch_failed', 'Consolidation batch {{batch}} failed: {{error}}', {batch: i + 1, error: error.message})}`);
        throw error;
      }
    }

    const finalMessage = getTranslation('transactions.consolidation_completed',
      'Consolidation completed!\n{{original}} UTXOs → {{final}} UTXO(s)\nTransactions: {{txCount}}\nType: {{type}}',
      { original: usableUtxos.length, final: numBatches, txCount: txids.length, type: sourceType }
    );
    await showInfoPopup(finalMessage);

    if (lastTxid && window.showSuccessPopup) {
      await window.showSuccessPopup(lastTxid);
    }

  } catch (error) {
    console.error(`[CONSOLIDATION] ${getTranslation('transactions.consolidation_error', 'Consolidation error: {{error}}', {error: error.message})}`);
    await showInfoPopup(getTranslation('transactions.consolidation_error', 'Consolidation error: {{error}}', {error: error.message}));
  } finally {
    if (window.endOperation) window.endOperation('consolidation');
    if (window.showSimpleProgressBar) {
      window.showSimpleProgressBar(null, false);
    }
  }
}

// === CREATE UNIFORM UTXOS ===
export async function createUniformUtxos(numUtxos, amountPerUtxoSats, destinationAddress) {
  let keyPair = null;
  
  try {
    const isHD = window.importType === 'hd';
    const hdWallet = isHD && window.hdManager ? window.hdManager.hdWallet : null;

    const selectedType = document.getElementById('debitAddressType')?.value || 'bech32';
    const sourceType = selectedType === 'p2tr' ? 'p2tr' : 'bech32';
    const inputType = sourceType === 'p2tr' ? 'p2tr' : 'p2wpkh';

    let sourceAddress = '';
    if (sourceType === 'p2tr') {
      sourceAddress = window.taprootAddress || '';
    } else {
      sourceAddress = window.bech32Address || '';
    }

    if (!sourceAddress) {
      throw new Error(getTranslation('transactions.source_address_not_found', 'Source address not found for type: {{type}}', { type: sourceType }));
    }

    const allUtxos = await utxos(sourceAddress, isHD, hdWallet);

    if (!allUtxos || allUtxos.length === 0) {
      throw new Error(getTranslation('transactions.no_utxos_available', 'No UTXOs available'));
    }

    const { usableUtxos } = filterUtxosByContext(allUtxos, 'normal');

    if (!usableUtxos.length) {
      throw new Error(getTranslation('transactions.no_suitable_utxos', 'No suitable mature UTXOs available'));
    }

    const transactionBuilder = new TransactionBuilder();
    const feeRate = await transactionBuilder.feeManager.getRealFeeRate();

    const vbytes = transactionBuilder.feeManager.estimateVBytes(inputType, 1, numUtxos + 1);
    const estimatedFee = transactionBuilder.feeManager.calculateFeeForVsize(vbytes, feeRate);
    const totalNeeded = (numUtxos * amountPerUtxoSats) + estimatedFee;

    const sortedUtxos = usableUtxos.sort((a, b) => b.amount - a.amount);

    let selectedUtxos = [];
    let totalInput = 0;

    for (const utxo of sortedUtxos) {
      selectedUtxos.push(utxo);
      totalInput += Math.round(utxo.amount * 1e8);

      if (totalInput >= totalNeeded) {
        break;
      }
    }

    if (totalInput < totalNeeded) {
      throw new Error(getTranslation('transactions.insufficient_funds_simple', 'Insufficient funds'));
    }

    const { bitcoin } = await getBitcoinLibraries();
    const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
    psbt.setVersion(2);

    for (const utxo of selectedUtxos) {
      const inputValue = Math.round(utxo.amount * 1e8);
      const scriptBuffer = Buffer.from(utxo.scriptPubKey, 'hex');

      if (utxo.scriptType === 'p2tr') {
        const enrichedUtxo = await TaprootUtils.prepareTaprootUtxo(utxo);
        psbt.addInput({
          hash: enrichedUtxo.txid,
          index: enrichedUtxo.vout,
          witnessUtxo: { script: scriptBuffer, value: inputValue },
          tapInternalKey: enrichedUtxo.tapInternalKey
        });
      } else {
        psbt.addInput({
          hash: utxo.txid,
          index: utxo.vout,
          witnessUtxo: { script: scriptBuffer, value: inputValue }
        });
      }
    }

    for (let i = 0; i < numUtxos; i++) {
      psbt.addOutput({
        address: destinationAddress,
        value: amountPerUtxoSats
      });
    }

    const changeAmount = totalInput - (numUtxos * amountPerUtxoSats) - estimatedFee;

    if (changeAmount > 546) {
      psbt.addOutput({
        address: destinationAddress,
        value: changeAmount
      });
    }

    for (let i = 0; i < selectedUtxos.length; i++) {
      const utxo = selectedUtxos[i];

      if (utxo.scriptType === 'p2tr') {
        const enrichedUtxo = await TaprootUtils.prepareTaprootUtxo(utxo);
        const tweakedSigner = TaprootUtils.tweakSigner(enrichedUtxo.keyPair);
        psbt.signInput(i, tweakedSigner);
        
        if (tweakedSigner.privateKey) tweakedSigner.privateKey.fill(0);
        if (enrichedUtxo.keyPair.privateKey) enrichedUtxo.keyPair.privateKey.fill(0);
      } else {
        keyPair = await transactionBuilder.getKeyPairForUtxo(utxo, sourceType);
        const publicKey = await transactionBuilder.getPublicKeyForUtxo(utxo, sourceType);
        const signer = {
          network: keyPair.network,
          privateKey: Buffer.from(keyPair.privateKey),
          publicKey: Buffer.from(publicKey),
          sign: (hash) => Buffer.from(keyPair.sign(hash))
        };
        psbt.signInput(i, signer);
        
        if (signer.privateKey) signer.privateKey.fill(0);
        if (keyPair.privateKey) keyPair.privateKey.fill(0);
        keyPair = null;
      }
    }

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const txHex = tx.toHex();
    const txid = await window.rpc('sendrawtransaction', [txHex]);

    console.log(`[UTXO-SPLIT] Created ${numUtxos} UTXOs: ${txid.substring(0, 8)}...`);

    await sleep(2000);

    const newUtxos = [];
    for (let i = 0; i < numUtxos; i++) {
      newUtxos.push({
        txid: txid,
        vout: i,
        amount: amountPerUtxoSats / 1e8,
        scriptPubKey: selectedUtxos[0].scriptPubKey,
        scriptType: inputType === 'p2tr' ? 'p2tr' : 'p2wpkh'
      });
    }

    return {
      txid,
      utxos: newUtxos
    };

  } catch (error) {
    console.error(`[UTXO-SPLIT] ${getTranslation('transactions.transaction_preparation_failed', 'Transaction preparation failed')}:`, error);
    throw error;
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

// === WAIT FOR TRANSACTION CONFIRMATION ===
export async function waitForTransactionConfirmation(txid, maxWaitTime = 600000) {
  const startTime = Date.now();
  console.log(`[TX-CONFIRM] ${getTranslation('confirmations.checking_confirmation', 'Checking confirmations...')} ${txid.substring(0, 8)}...`);

  while (Date.now() - startTime < maxWaitTime) {
    try {
      if (!window.rpc) {
        await sleep(10000);
        continue;
      }

      const utxoInfo = await window.rpc('gettxout', [txid, 0, true]);

      if (utxoInfo && utxoInfo.confirmations && utxoInfo.confirmations >= 1) {
        console.log(`[TX-CONFIRM] ${getTranslation('confirmations.confirmed', 'Confirmed')} ${txid.substring(0, 8)}... (${utxoInfo.confirmations} confirmations)`);
        return true;
      }

      await sleep(10000);
    } catch (error) {
      console.warn(`[TX-CONFIRM] ${getTranslation('explorer.checking_explorer', 'Error while checking explorer:')}`, error);
      await sleep(10000);
    }
  }

  console.warn(`[TX-CONFIRM] Timeout for ${txid.substring(0, 8)}...`);
  return false;
}

// === GLOBAL EXPORTS ===
if (typeof window !== 'undefined') {
  window.filterUtxosByContext = filterUtxosByContext;
  window.calculateMaxSendableAmount = calculateMaxSendableAmount;
  window.consolidateUTXOs = consolidateUTXOs;
  window.consolidateUtxos = consolidateUTXOs;
  window.createUniformUtxos = createUniformUtxos;
  window.waitForTransactionConfirmation = waitForTransactionConfirmation;
  window.broadcastWithRetry = broadcastWithRetry;
  window.filterUtxosByMinValue = filterUtxosByMinValue;
  window.FeeManager = FeeManager;
  window.TransactionBuilder = TransactionBuilder;
}

export default TransactionBuilder;