// Transaction Management for NITO Wallet
// Handles transaction creation, signing, and UTXO consolidation 

import { NITO_NETWORK, TRANSACTION_CONFIG, ELEMENT_IDS, OPERATION_STATE } from './config.js';
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
async function getWalletInfo() {
  return new Promise((resolve) => {
    eventBus.once(EVENTS.WALLET_INFO_RESPONSE, resolve, { timeout: 3000 });
    eventBus.emit(EVENTS.WALLET_INFO_REQUEST);
  }).catch(() => {
    return { address: '', isReady: false, addresses: {} };
  });
}

// === OPERATIONS TRACKING ===
function startOperation(operationType) {
  if (typeof window.startOperation === 'function') {
    window.startOperation(operationType);
  } else {
    OPERATION_STATE.activeOperations.add(operationType);
    console.log(`[OPERATION] Started: ${operationType}`);
  }
}

function endOperation(operationType) {
  if (typeof window.endOperation === 'function') {
    window.endOperation(operationType);
  } else {
    OPERATION_STATE.activeOperations.delete(operationType);
    console.log(`[OPERATION] Ended: ${operationType}`);
  }
}

function isOperationActive(operationType = null) {
  if (typeof window.isOperationActive === 'function') {
    return window.isOperationActive(operationType);
  } else {
    if (operationType) {
      return OPERATION_STATE.activeOperations.has(operationType);
    }
    return OPERATION_STATE.activeOperations.size > 0;
  }
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
      console.log(`[FEE] Real fee rate: ${realRate} NITO/vB`);
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
    
    console.log(`[FEE] Estimated vBytes: ${totalVBytes} (${numInputs} ${inputType} inputs, ${numOutputs} outputs)`);
    return totalVBytes;
  }
}

// Enhanced Taproot utilities with proper key management
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

    console.log('[TAPROOT] Tweaking signer for taproot transaction');

    let privateKey = Buffer.from(signer.privateKey);
    const publicKey = Buffer.from(signer.publicKey);
    
    // Check if we need to negate the private key
    if (publicKey[0] === 3) {
      console.log('[TAPROOT] Negating private key for odd y-coordinate');
      privateKey = bitcoin.crypto.privateNegate(privateKey);
    }
    
    const tweakHash = opts.tweakHash ? Buffer.from(opts.tweakHash) : Buffer.alloc(0);
    const tapTweakHash = bitcoin.crypto.taggedHash('TapTweak', Buffer.concat([TaprootUtils.toXOnly(publicKey), tweakHash]));
    const tweak = Buffer.from(tapTweakHash);
    const tweakedPrivateKey = bitcoin.crypto.privateAdd(privateKey, tweak);
    
    if (!tweakedPrivateKey) {
      const errorMsg = getTranslation('security.invalid_tweaked_key', 'Clé privée modifiée invalide');
      throw new Error(errorMsg);
    }
    
    const tweakedPublicKey = bitcoin.crypto.pointFromScalar(tweakedPrivateKey, true);
    
    console.log('[TAPROOT] Signer tweaked successfully');
    
    return {
      publicKey: Buffer.from(tweakedPublicKey),
      signSchnorr: (hash) => {
        const randomBytes = crypto.getRandomValues(new Uint8Array(32));
        return bitcoin.crypto.signSchnorr(hash, tweakedPrivateKey, Buffer.from(randomBytes));
      }
    };
  }

  static async prepareTaprootUtxo(utxo, hdWallet) {
    try {
      if (!hdWallet || utxo.scriptType !== 'p2tr') {
        return utxo;
      }

      console.log(`[TAPROOT] Preparing taproot UTXO: ${utxo.txid}:${utxo.vout}`);

      // If UTXO already has taproot data, return as-is
      if (utxo.tapInternalKey && utxo.keyPair) {
        console.log('[TAPROOT] UTXO already has taproot data');
        return utxo;
      }

      // Try to derive the key pair for this UTXO
      if (hdWallet.deriveKeyFor) {
        // We need to find which derivation path this UTXO belongs to
        // For now, try the standard taproot path
        try {
          const keyInfo = hdWallet.deriveKeyFor('taproot', 0, 0);
          if (keyInfo && keyInfo.keyPair && keyInfo.tapInternalKey) {
            console.log('[TAPROOT] Successfully derived key pair for UTXO');
            return {
              ...utxo,
              keyPair: keyInfo.keyPair,
              tapInternalKey: keyInfo.tapInternalKey
            };
          }
        } catch (error) {
          console.warn('[TAPROOT] Could not derive key pair for UTXO:', error);
        }
      }

      // Fallback: try to get from global taproot functions
      if (window.getTaprootKeyPair && window.getTaprootPublicKey) {
        const keyPair = await window.getTaprootKeyPair();
        const taprootPublicKey = await window.getTaprootPublicKey();
        
        if (keyPair && taprootPublicKey) {
          console.log('[TAPROOT] Using global taproot key pair');
          return {
            ...utxo,
            keyPair: keyPair,
            tapInternalKey: Buffer.from(taprootPublicKey)
          };
        }
      }

      console.warn('[TAPROOT] Could not prepare taproot UTXO - missing key data');
      return utxo;
    } catch (error) {
      console.error('[TAPROOT] Error preparing taproot UTXO:', error);
      return utxo;
    }
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

// Main transaction builder class with full Taproot support
export class SimpleTransactionBuilder {
  constructor() {
    this.feeManager = new FeeManager();
  }

  async signTxWithPSBT(to, amt, isConsolidation = false) {
    if (isOperationActive('transaction')) {
      console.log('[TX] Transaction already in progress');
      throw new Error('Transaction déjà en cours. Veuillez attendre.');
    }

    startOperation('transaction');
    armInactivityTimerSafely();
    
    try {
      const walletInfo = await getWalletInfo();
      if (!walletInfo.isReady) {
        const errorMsg = getTranslation('errors.import_first', 'Importez d\'abord un wallet.');
        throw new Error(errorMsg);
      }

      const selectedAddressType = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE)?.value || 'bech32';
      
      let sourceAddress;
      if (selectedAddressType === 'p2tr') {
        sourceAddress = walletInfo.addresses.taproot;
        console.log('[TX] Using taproot address:', sourceAddress);
      } else {
        sourceAddress = walletInfo.addresses.bech32;
        console.log('[TX] Using bech32 address:', sourceAddress);
      }
      
      if (!sourceAddress) {
        throw new Error(`Adresse source non trouvée pour le type: ${selectedAddressType}`);
      }
      
      if (!window.utxos) {
        const errorMsg = getTranslation('errors.transaction_functions_unavailable', 'Fonctions de transaction non disponibles');
        throw new Error(errorMsg);
      }

      const hdWallet = window.hdManager ? window.hdManager.hdWallet : null;
      const isHD = window.importType === 'hd';

      console.log(`[TX] Fetching UTXOs for ${selectedAddressType} (HD: ${isHD})`);
      const rawUtxos = await window.utxos(sourceAddress, isHD, hdWallet);
      
      if (!rawUtxos.length) {
        const errorMsg = getTranslation('transactions.no_utxos_for_consolidation', 'Aucun UTXO disponible');
        throw new Error(errorMsg);
      }

      console.log(`[TX] Found ${rawUtxos.length} raw UTXOs`);
      const matureUtxos = await filterMatureUtxos(rawUtxos);
      
      if (!matureUtxos.length) {
        const errorMsg = getTranslation('transactions.no_suitable_utxos', 'Aucun UTXO mature approprié disponible');
        throw new Error(errorMsg);
      }

      console.log(`[TX] Found ${matureUtxos.length} mature UTXOs`);

      // Filter UTXOs by address type and prepare taproot UTXOs
      let workingUtxos;
      if (isConsolidation) {
        if (selectedAddressType === 'p2tr') {
          workingUtxos = matureUtxos.filter(u => u.scriptType === 'p2tr');
          // Prepare taproot UTXOs
          workingUtxos = await Promise.all(
            workingUtxos.map(utxo => TaprootUtils.prepareTaprootUtxo(utxo, hdWallet))
          );
        } else {
          workingUtxos = matureUtxos.filter(u => ['p2wpkh', 'p2pkh', 'p2sh'].includes(u.scriptType));
        }
      } else {
        const filteredUtxos = window.filterOpReturnUtxos ? await window.filterOpReturnUtxos(matureUtxos) : matureUtxos;
        if (selectedAddressType === 'p2tr') {
          workingUtxos = filteredUtxos.filter(u => u.scriptType === 'p2tr');
          // Prepare taproot UTXOs
          workingUtxos = await Promise.all(
            workingUtxos.map(utxo => TaprootUtils.prepareTaprootUtxo(utxo, hdWallet))
          );
        } else {
          workingUtxos = filteredUtxos.filter(u => ['p2wpkh', 'p2pkh', 'p2sh'].includes(u.scriptType));
        }
      }

      if (!workingUtxos.length) {
        const errorMsg = getTranslation('transactions.no_suitable_utxos', `Aucun UTXO ${selectedAddressType} mature approprié disponible`);
        throw new Error(errorMsg);
      }

      console.log(`[TX] Found ${workingUtxos.length} working UTXOs for ${selectedAddressType}`);

      const target = Math.round(amt * 1e8);
      workingUtxos.sort((a, b) => b.amount - a.amount);

      let selectedUtxos, total;

      if (isConsolidation) {
        selectedUtxos = [...workingUtxos];
        total = selectedUtxos.reduce((s, u) => s + Math.round(u.amount * 1e8), 0);
        console.log(`[TX] Consolidation: using all ${selectedUtxos.length} UTXOs, total: ${total} satoshis`);
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
          
          console.log(`[TX] Current: ${selectedUtxos.length} UTXOs, total: ${total}, target+fees: ${target + estimatedFees}`);
          
          if (total >= target + estimatedFees) {
            break;
          }
        }
        
        const finalInputType = selectedAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh';
        const finalVbytes = this.feeManager.estimateVBytes(finalInputType, selectedUtxos.length);
        const finalFees = this.feeManager.calculateFeeForVsize(finalVbytes, realFeeRate);
        
        if (total < target + finalFees) {
          const shortfall = (target + finalFees - total) / 1e8;
          const errorMsg = getTranslation('transactions.insufficient_funds_detailed', 
            `Fonds insuffisants. Utilisez le bouton MAX ou réduisez le montant de ${shortfall.toFixed(8)} NITO pour couvrir les frais.`,
            { amount: shortfall.toFixed(8) }
          );
          throw new Error(errorMsg);
        }

        console.log(`[TX] Selected ${selectedUtxos.length} UTXOs for transaction`);
      }

      return await this.buildAndSignTransaction(to, target, selectedUtxos, isConsolidation, selectedAddressType);
    } finally {
      endOperation('transaction');
    }
  }

  async buildAndSignTransaction(to, target, selectedUtxos, isConsolidation, sourceAddressType) {
    const { bitcoin } = await getBitcoinLibraries();
    
    console.log(`[TX] Building transaction: ${sourceAddressType}, ${selectedUtxos.length} UTXOs`);
    
    const realFeeRate = await this.feeManager.getRealFeeRate();
    const inputType = sourceAddressType === 'p2tr' ? 'p2tr' : 'p2wpkh';
    const outputCount = isConsolidation ? 1 : 2; // Consolidation has no change output
    const vbytes = this.feeManager.estimateVBytes(inputType, selectedUtxos.length, outputCount);
    const fees = this.feeManager.calculateFeeForVsize(vbytes, realFeeRate);
    
    const total = selectedUtxos.reduce((s, u) => s + Math.round(u.amount * 1e8), 0);
    const change = total - target - fees;
    
    console.log(`[TX] Transaction details: total=${total}, target=${target}, fees=${fees}, change=${change}`);
    
    if (change < 0) {
      const errorMsg = getTranslation('transactions.insufficient_funds_after_fees', 'Fonds insuffisants après calcul des frais');
      throw new Error(errorMsg);
    }

    const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
    psbt.setVersion(2);

    // Add inputs
    for (const utxo of selectedUtxos) {
      await this.addInputToPsbt(psbt, utxo, sourceAddressType);
    }

    // Add output
    psbt.addOutput({ address: to, value: target });
    console.log(`[TX] Added output: ${target} satoshis to ${to}`);

    // Add change output if needed
    const dustThreshold = sourceAddressType === 'p2tr' ? 330 : 294;
    if (change > dustThreshold && !isConsolidation) {
      const walletInfo = await getWalletInfo();
      const changeAddress = sourceAddressType === 'p2tr' ? walletInfo.addresses.taproot : walletInfo.addresses.bech32;
      psbt.addOutput({ address: changeAddress, value: change });
      console.log(`[TX] Added change output: ${change} satoshis to ${changeAddress}`);
    }

    // Sign all inputs
    await this.signPsbtInputs(psbt, selectedUtxos, sourceAddressType);

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    const hex = tx.toHex();

    console.log(`[TX] Transaction built successfully, hex length: ${hex.length}`);
    
    return { hex, actualFees: fees / 1e8 };
  }

  async addInputToPsbt(psbt, utxo, addressType) {
    const scriptBuffer = Buffer.from(utxo.scriptPubKey, 'hex');
    const value = Math.round(utxo.amount * 1e8);
    
    console.log(`[TX] Adding input: ${utxo.txid}:${utxo.vout}, type: ${utxo.scriptType}, value: ${value}`);
    
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
      console.log('[TX] Adding taproot input');
      
      let tapInternalKey = utxo.tapInternalKey;
      
      // Fallback to derive tapInternalKey if not present
      if (!tapInternalKey && utxo.keyPair) {
        tapInternalKey = TaprootUtils.toXOnly(utxo.keyPair.publicKey);
        console.log('[TX] Derived tapInternalKey from keyPair');
      }
      
      if (!tapInternalKey) {
        // Try to get from global functions
        if (window.getTaprootPublicKey) {
          const taprootPubKey = await window.getTaprootPublicKey();
          if (taprootPubKey) {
            tapInternalKey = Buffer.from(taprootPubKey);
            console.log('[TX] Got tapInternalKey from global function');
          }
        }
      }
      
      if (!tapInternalKey) {
        throw new Error('tapInternalKey manquant pour l\'UTXO taproot');
      }
      
      console.log('[TX] Using tapInternalKey:', tapInternalKey.toString('hex'));
      
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
    console.log(`[TX] Signing ${selectedUtxos.length} inputs for ${addressType}`);
    
    for (let i = 0; i < selectedUtxos.length; i++) {
      const utxo = selectedUtxos[i];
      
      if (utxo.scriptType === 'p2tr') {
        console.log(`[TX] Signing taproot input ${i}`);
        
        let keyPair = utxo.keyPair;
        
        // Fallback to get keyPair if not present
        if (!keyPair && window.getTaprootKeyPair) {
          keyPair = await window.getTaprootKeyPair();
          console.log('[TX] Got taproot keyPair from global function');
        }
        
        if (!keyPair) {
          throw new Error(`KeyPair manquant pour l'UTXO taproot ${i}`);
        }
        
        const tweaked = await TaprootUtils.tweakSigner(keyPair, { network: NITO_NETWORK });
        psbt.signInput(i, tweaked);
        console.log(`[TX] Taproot input ${i} signed successfully`);
      } else {
        console.log(`[TX] Signing ${utxo.scriptType} input ${i}`);
        
        let keyPair = utxo.keyPair;
        
        // Fallback to get keyPair if not present
        if (!keyPair && window.getWalletKeyPair) {
          keyPair = await window.getWalletKeyPair();
          console.log('[TX] Got wallet keyPair from global function');
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
        console.log(`[TX] ${utxo.scriptType} input ${i} signed successfully`);
      }
    }
  }
}

// Enhanced consolidate UTXOs with full Taproot support
export async function consolidateUtxos() {
  if (isOperationActive('consolidation')) {
    console.log('[CONSOLIDATION] Consolidation already in progress');
    alert('Consolidation déjà en cours. Veuillez attendre.');
    return;
  }

  startOperation('consolidation');
  armInactivityTimerSafely();
  console.log('[CONSOLIDATION] Starting consolidation...');

  try {
    const walletInfo = await getWalletInfo();
    if (!walletInfo.isReady) {
      const alertMsg = getTranslation('errors.import_first', 'Importez d\'abord un wallet.');
      alert(alertMsg);
      return;
    }

    const sourceType = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE)?.value || 'bech32';
    console.log(`[CONSOLIDATION] Source type: ${sourceType}`);

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
      console.log('[CONSOLIDATION] Fetching taproot UTXOs for:', taprootAddress);
      
      if (!taprootAddress) {
        throw new Error('Adresse taproot non disponible');
      }
      
      rawUtxos = await window.utxos(taprootAddress, isHD, hdWallet);
      rawUtxos = rawUtxos.filter(u => u.scriptType === 'p2tr');
      
      // Prepare taproot UTXOs with key pairs
      console.log(`[CONSOLIDATION] Preparing ${rawUtxos.length} taproot UTXOs`);
      rawUtxos = await Promise.all(
        rawUtxos.map(utxo => TaprootUtils.prepareTaprootUtxo(utxo, hdWallet))
      );
      
      console.log(`[CONSOLIDATION] Found ${rawUtxos.length} taproot UTXOs`);
    } else {
      const bech32Address = walletInfo.addresses.bech32;
      console.log('[CONSOLIDATION] Fetching bech32 UTXOs for:', bech32Address);
      
      if (isHD && hdWallet) {
        rawUtxos = await window.utxos(bech32Address, true, hdWallet);
        rawUtxos = rawUtxos.filter(u => ['p2wpkh', 'p2pkh', 'p2sh'].includes(u.scriptType));
      } else {
        rawUtxos = await window.utxos(bech32Address, false, null);
        rawUtxos = rawUtxos.filter(u => u.scriptType === 'p2wpkh');
      }
      
      console.log(`[CONSOLIDATION] Found ${rawUtxos.length} bech32 UTXOs`);
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

    console.log(`[CONSOLIDATION] Found ${allUtxos.length} mature UTXOs for consolidation`);

    const totalValue = allUtxos.reduce((sum, u) => sum + u.amount, 0);

    const MAX_UTXOS_PER_BATCH = sourceType === 'p2tr' ? 1000 : 1500; // Taproot inputs are smaller
    const batches = [];
    
    for (let i = 0; i < allUtxos.length; i += MAX_UTXOS_PER_BATCH) {
      const batch = allUtxos.slice(i, i + MAX_UTXOS_PER_BATCH);
      batches.push(batch);
    }

    console.log(`[CONSOLIDATION] Created ${batches.length} batches`);

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
    console.log(`[CONSOLIDATION] Destination address: ${destinationAddress}`);

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      const batchTotal = batch.reduce((sum, u) => sum + u.amount, 0);
      
      console.log(`[CONSOLIDATION] Processing batch ${i + 1}/${batches.length} with ${batch.length} UTXOs`);
      
      const realFeeRate = await transactionBuilder.feeManager.getRealFeeRate();
      const inputType = sourceType === 'p2tr' ? 'p2tr' : 'p2wpkh';
      const vbytes = transactionBuilder.feeManager.estimateVBytes(inputType, batch.length, 1);
      const estimatedFee = transactionBuilder.feeManager.calculateFeeForVsize(vbytes, realFeeRate) / 1e8;
      const netAmount = batchTotal - estimatedFee;

      console.log(`[CONSOLIDATION] Batch ${i + 1}: total=${batchTotal}, fee=${estimatedFee}, net=${netAmount}`);

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
          const errorMsg = getTranslation('errors.rpc_unavailable', 'Fonction RPC non disponible');
          throw new Error(errorMsg);
        }
        
        console.log(`[CONSOLIDATION] Broadcasting batch ${i + 1}...`);
        const txid = await window.rpc('sendrawtransaction', [result.hex]);
        txids.push(txid);
        
        console.log(`[CONSOLIDATION] Batch ${i + 1} broadcast: ${txid}`);
        
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
    
    console.log(`[CONSOLIDATION] Completed successfully: ${txids.length} transactions`);
    
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
    console.error('[CONSOLIDATION] Error:', e);
  } finally {
    endOperation('consolidation');
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

console.log('Transactions module loaded - Version 2.0.0');
