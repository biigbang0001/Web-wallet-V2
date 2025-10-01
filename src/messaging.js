// Encrypted Messaging System for NITO Wallet

import { MESSAGING_CONFIG, NITO_NETWORK, ELEMENT_IDS, NODE_CONFIG, FEATURE_FLAGS, getTranslation } from './config.js';
import { eventBus, EVENTS } from './events.js';
import { waitForLibraries, getBitcoinLibraries } from './vendor.js';
import { handleError500WithRetry } from './blockchain.js';
import {
  showScanProgress,
  showMessageModal,
  createMessageProgressIndicator,
  updateMessageProgress,
  closeMessageProgress
} from './ui-popups.js';

// === WALLET STATE ACCESS VIA EVENTS ===
let walletInfoCache = { address: '', isReady: false, addresses: {} };
let lastWalletInfoCheck = 0;
const WALLET_INFO_CACHE_DURATION = 5000;

async function getWalletInfo() {
  const now = Date.now();

  if (now - lastWalletInfoCheck < WALLET_INFO_CACHE_DURATION) {
    return walletInfoCache;
  }

  try {
    if (window.isWalletReady && window.isWalletReady()) {
      const address = window.getWalletAddress ? window.getWalletAddress() : '';
      const bech32Address = window.getBech32Address ? await window.getBech32Address() : address;

      walletInfoCache = {
        address: bech32Address,
        isReady: true,
        addresses: {
          bech32: bech32Address,
          legacy: window.legacyAddress || '',
          p2sh: window.p2shAddress || '',
          taproot: window.taprootAddress || ''
        }
      };
      lastWalletInfoCheck = now;

      return walletInfoCache;
    }

    return walletInfoCache;
  } catch (error) {
    console.warn('[MESSAGING] getWalletInfo error:', error);
    return walletInfoCache;
  }
}

async function getWalletKeyPair() {
  if (window.getWalletKeyPair) {
    return window.getWalletKeyPair();
  }
  return null;
}

async function getWalletPublicKey() {
  if (window.getWalletPublicKey) {
    return window.getWalletPublicKey();
  }
  return null;
}

// === MESSAGING STATE MANAGEMENT ===
let messagingState = {
  keyPair: null,
  publicKey: null,
  bech32Address: null,
  isInitialized: false,
  sessionFeeRate: null,
  interfaceSetup: false
};

// === GLOBAL FLAGS TO PREVENT DUPLICATIONS ===
let messagingInitialized = false;
let initializationInProgress = false;
let buttonListenersSetup = false;

// === MAIN MESSAGING CLASS ===
export class NitoMessaging {
  constructor() {
    this.__sessionFeeRate = null;
    this.messageCache = new Map();
    this.deletedMessages = new Set();
    this.usedUtxos = new Set();
    this.txDetailCache = new Map();
    this.initialized = false;
    this.initializationPromise = null;
  }

  // === TIMING HELPERS ===
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async sleepJitter(baseMs = 1, maxJitterMs = 300, active = false) {
    const extra = active ? Math.floor(Math.random() * (maxJitterMs + 1)) : 0;
    await this.sleep(baseMs + extra);
  }

  // === UTXO MANAGEMENT ===
  markUtxoAsUsed(txid, vout) {
    const utxoId = `${txid}:${vout}`;
    this.usedUtxos.add(utxoId);
  }

  releaseUtxo(txid, vout) {
    const utxoId = `${txid}:${vout}`;
    this.usedUtxos.delete(utxoId);
  }

  async getAvailableUtxos(address) {
    return await handleError500WithRetry(async () => {
      const scan = await window.rpc("scantxoutset", ["start", [`addr(${address})`]]);
      if (!scan.success || !scan.unspents) return [];

      const viableUtxos = scan.unspents
        .filter(u => u.amount >= 0.000003)
        .map(u => ({
          txid: u.txid,
          vout: u.vout,
          amount: u.amount,
          scriptPubKey: u.scriptPubKey,
          id: `${u.txid}:${u.vout}`
        }))
        .sort((a, b) => b.amount - a.amount);

      const availableUtxos = viableUtxos.filter(utxo => !this.usedUtxos.has(utxo.id));

      if (availableUtxos.length > 0) {
        console.log(`[MESSAGING] Largest available UTXO: ${availableUtxos[0].amount} NITO`);
      }

      return availableUtxos;
    });
  }

  async isInboundMessageUtxo(utxo) {
    try {
      const tx = this.txDetailCache.has(utxo.txid)
        ? this.txDetailCache.get(utxo.txid)
        : await this.getTxDetailCached(utxo.txid);
      const hasMsg = (tx.vout || []).some(v => {
        const hex = v.scriptPubKey && v.scriptPubKey.hex;
        if (!hex) return false;
        const data = this.extractOpReturnData(hex);
        return !!(data && data.startsWith(MESSAGING_CONFIG.MESSAGE_PREFIX));
      });
      return !!hasMsg;
    } catch (e) {
      return false;
    }
  }

  async getTxDetailCached(txid) {
    if (this.txDetailCache.has(txid)) return this.txDetailCache.get(txid);

    const t = await handleError500WithRetry(async () => {
      return await window.rpc('getrawtransaction', [txid, true]);
    });

    this.txDetailCache.set(txid, t);
    return t;
  }

  // === FEE CALCULATION ===
  async computeAdaptiveChunkAmount(feeRateOverride) {
    const estTxVBytes = 250;
    const feeRate = (feeRateOverride != null) ? feeRateOverride
                : (this.__sessionFeeRate != null) ? this.__sessionFeeRate
                : await this.getEffectiveFeeRate();
    const estFee = (estTxVBytes * (feeRate * 1e8) / 1000) / 1e8;
    const minFunding = (MESSAGING_CONFIG.MESSAGE_FEE + estFee) * 1.05;
    return Math.round(minFunding * 1e8) / 1e8;
  }

  async getEffectiveFeeRate() {
    try {
      const [info, net, est] = await Promise.all([
        handleError500WithRetry(() => window.rpc('getmempoolinfo', [])),
        handleError500WithRetry(() => window.rpc('getnetworkinfo', [])),
        handleError500WithRetry(() => window.rpc('estimatesmartfee', [2])).catch(() => null)
      ]);
      const cfg = window.DYNAMIC_FEE_RATE || 0.00001;
      const nodeMin = Math.max((info && info.mempoolminfee) || 0, (net && net.relayfee) || 0);
      const estRate = (est && est.feerate) ? est.feerate : 0;
      return Math.max(cfg, nodeMin, estRate);
    } catch (e) {
      return window.DYNAMIC_FEE_RATE || 0.00001;
    }
  }

  // === INITIALIZATION ===
  async initialize() {
    if (messagingState.isInitialized) {
      return true;
    }

    if (window.isWalletReady && window.isWalletReady() && window.getWalletAddress && window.rpc) {
      messagingState.keyPair = null;
      messagingState.publicKey = null;
      messagingState.bech32Address = window.getWalletAddress();
      messagingState.isInitialized = true;
      return true;
    }
    return false;
  }

  checkInitialized() {
    if (!messagingState.isInitialized) {
      throw new Error(getTranslation('messaging.wallet_not_initialized', 'Wallet not initialized'));
    }
  }

  // === CRYPTOGRAPHY ===
  async deriveSharedKey(myPrivateKey, theirPublicKey) {
    try {
      if (!myPrivateKey || !theirPublicKey) {
        throw new Error(getTranslation('messaging.missing_keys_ecdh', 'Missing keys for ECDH'));
      }

      if (!window.secp256k1) {
        throw new Error(getTranslation('messaging.secp256k1_unavailable', 'secp256k1 library not available'));
      }

      const privateKeyHex = Buffer.from(myPrivateKey).toString('hex');
      const publicKeyHex = Buffer.from(theirPublicKey).toString('hex');

      if (!window.secp256k1.utils.isValidPrivateKey(privateKeyHex)) {
        throw new Error(getTranslation('messaging.invalid_private_key', 'Invalid private key'));
      }

      const sharedPoint = window.secp256k1.getSharedSecret(privateKeyHex, publicKeyHex, true);
      const hashBuffer = await crypto.subtle.digest('SHA-256', sharedPoint);
      const derivedKey = new Uint8Array(hashBuffer);

      return derivedKey;

    } catch (error) {
      console.error('[MESSAGING] ECDH error:', error);
      throw new Error(`${getTranslation('messaging.shared_key_derivation_error', 'Shared key derivation error')}: ${error.message}`);
    }
  }

  async encryptWithAES(data, key) {
    try {
      const iv = crypto.getRandomValues(new Uint8Array(12));

      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key.slice(0, 32),
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );

      const dataBuffer = new TextEncoder().encode(data);
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        cryptoKey,
        dataBuffer
      );

      const result = new Uint8Array(iv.length + encrypted.byteLength);
      result.set(iv, 0);
      result.set(new Uint8Array(encrypted), iv.length);

      const base64Result = btoa(String.fromCharCode(...result));

      return base64Result;

    } catch (error) {
      console.error('[MESSAGING] AES encryption error:', error);
      throw new Error(`${getTranslation('messaging.encryption_error', 'Encryption error')}: ${error.message}`);
    }
  }

  async decryptWithAES(encryptedData, key) {
    try {
      const encrypted = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));

      const iv = encrypted.slice(0, 12);
      const ciphertext = encrypted.slice(12);

      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key.slice(0, 32),
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        cryptoKey,
        ciphertext
      );

      const result = new TextDecoder().decode(decrypted);

      return result;

    } catch (error) {
      console.error('[MESSAGING] AES decryption error:', error);
      throw new Error(`${getTranslation('messaging.decryption_error', 'Decryption error')}: ${error.message}`);
    }
  }

  async hashMessage(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // === PUBLIC KEY MANAGEMENT ===
  async publishPublicKey() {
    if (window.isOperationActive && window.isOperationActive('publish_pubkey')) {
      throw new Error(getTranslation('messaging.publication_in_progress', 'Publication already in progress'));
    }

    if (window.startOperation) window.startOperation('publish_pubkey');

    try {
      this.checkInitialized();

      const publicKey = await getWalletPublicKey();
      const publicKeyHex = Buffer.from(publicKey).toString('hex');
      const opReturnData = `NITOPUB:${publicKeyHex}`;

      let availableUtxos = await this.getAvailableUtxos(messagingState.bech32Address);
      availableUtxos = availableUtxos.filter(utxo => utxo.amount >= 0.000003);
      if (availableUtxos.length === 0) {
        throw new Error(getTranslation('messaging.no_utxo_for_pubkey', 'No UTXO available to publish public key'));
      }

      const hex = await this.createOpReturnTransaction(
        messagingState.bech32Address,
        MESSAGING_CONFIG.MESSAGE_FEE,
        opReturnData,
        availableUtxos[0]
      );

      const txid = await handleError500WithRetry(async () => {
        return await window.rpc('sendrawtransaction', [hex]);
      });

      console.log('[MESSAGING] Public key published, TXID:', txid);

      if (window.showSuccessPopup) {
        await window.showSuccessPopup(txid);
      }

      return { success: true, txid, publicKey: publicKeyHex };
    } catch (error) {
      console.error('[MESSAGING] Public key publication error:', error);
      throw new Error(`${getTranslation('messaging.publication_error', 'Publication error')}: ${error.message}`);
    } finally {
      if (window.endOperation) window.endOperation('publish_pubkey');
    }
  }

  async findPublicKey(bech32Address) {
    try {
      if (!bech32Address || bech32Address === "null" || bech32Address === "unknown_sender") {
        return null;
      }

      const scan = await handleError500WithRetry(async () => {
        return await window.rpc("scantxoutset", ["start", [`addr(${bech32Address})`]]);
      });

      if (!scan.unspents) {
        return null;
      }

      for (const utxo of scan.unspents) {
        try {
          const tx = await handleError500WithRetry(async () => {
            return await window.rpc("getrawtransaction", [utxo.txid, true]);
          });

          for (const output of tx.vout) {
            if (output.scriptPubKey && output.scriptPubKey.hex) {
              const opReturnData = this.extractOpReturnData(output.scriptPubKey.hex);

              if (opReturnData && opReturnData.startsWith("NITOPUB:")) {
                const publicKeyHex = opReturnData.substring(8);

                if (publicKeyHex.length === 66 || publicKeyHex.length === 64) {
                  const publicKeyBuffer = Buffer.from(publicKeyHex, "hex");
                  return publicKeyBuffer;
                }
              }
            }
          }
        } catch (e) {
          console.warn(`[MESSAGING] Transaction analysis error ${utxo.txid}:`, e.message);
        }
      }

      return null;
    } catch (error) {
      console.error("[MESSAGING] Public key search error:", error);
      throw error;
    } finally {
      this.__sessionFeeRate = null;
    }
  }

  // === MESSAGE ENCRYPTION/DECRYPTION ===
  async encryptMessage(message, recipientBech32Address) {
    this.checkInitialized();

    try {
      const recipientPublicKey = await this.findPublicKey(recipientBech32Address);
      if (!recipientPublicKey) {
        throw new Error(getTranslation('messaging.recipient_pubkey_not_found',
          'Recipient public key not found. Recipient must first publish their public key.'));
      }

      const messageData = {
        content: message,
        sender: messagingState.bech32Address,
        recipient: recipientBech32Address,
        timestamp: Date.now(),
        messageId: this.generateMessageId()
      };

      const messageJson = JSON.stringify(messageData);

      const walletKeyPair = await getWalletKeyPair();
      const sharedKey = await this.deriveSharedKey(
        walletKeyPair.privateKey,
        recipientPublicKey
      );

      const encryptedMessage = await this.encryptWithAES(messageJson, sharedKey);

      const signature = await this.hashMessage(messageData.messageId + messageData.timestamp + messagingState.bech32Address);

      const finalMessage = {
        data: encryptedMessage,
        signature: signature,
        messageId: messageData.messageId,
        timestamp: messageData.timestamp,
        sender: messagingState.bech32Address,
        recipient: recipientBech32Address,
        senderPublicKey: Buffer.from(await getWalletPublicKey()).toString('hex'),
        recipientPublicKey: Buffer.from(recipientPublicKey).toString('hex')
      };

      return JSON.stringify(finalMessage);

    } catch (error) {
      console.error('[MESSAGING] ECDH encryption error:', error);
      throw error;
    }
  }

  async decryptMessage(encryptedMessage, senderAddress) {
    this.checkInitialized();

    try {
      if (!encryptedMessage || typeof encryptedMessage !== 'string') {
        throw new Error(getTranslation('messaging.empty_invalid_message', 'Empty or invalid message'));
      }

      let messageEnvelope;
      try {
        messageEnvelope = JSON.parse(encryptedMessage);
      } catch (e) {
        throw new Error(getTranslation('messaging.invalid_message_format', 'Invalid message format'));
      }

      if (messageEnvelope.recipient !== messagingState.bech32Address) {
        throw new Error(getTranslation('messaging.message_not_for_you', 'This message is not for you'));
      }

      let senderPublicKey;
      if (messageEnvelope.senderPublicKey) {
        senderPublicKey = Buffer.from(messageEnvelope.senderPublicKey, 'hex');
      } else {
        senderPublicKey = await this.findPublicKey(messageEnvelope.sender);
        if (!senderPublicKey) {
          throw new Error(getTranslation('messaging.sender_pubkey_not_found',
            'Unable to find sender\'s public key'));
        }
      }

      const walletKeyPair = await getWalletKeyPair();
      const sharedKey = await this.deriveSharedKey(
        walletKeyPair.privateKey,
        senderPublicKey
      );

      const decryptedJson = await this.decryptWithAES(messageEnvelope.data, sharedKey);

      let decryptedMessage;
      try {
        decryptedMessage = JSON.parse(decryptedJson);
      } catch (e) {
        throw new Error(getTranslation('messaging.decryption_parse_error', 'Error parsing decrypted message'));
      }

      const expectedSignature = await this.hashMessage(
        decryptedMessage.messageId +
        decryptedMessage.timestamp +
        decryptedMessage.sender
      );
      const verified = expectedSignature === messageEnvelope.signature;

      return {
        ...decryptedMessage,
        verified
      };

    } catch (error) {
      console.error("[MESSAGING] ECDH decryption error:", error);
      throw error;
    }
  }

  // === TRANSACTION CREATION ===
  async createOpReturnTransaction(toAddress, amount, opReturnData, specificUtxo, feeRateOverride = null) {
    this.checkInitialized();

    try {
      if (!specificUtxo) {
        throw new Error(getTranslation('messaging.specific_utxo_required', 'Specific UTXO required'));
      }

      const target = Math.round(amount * 1e8);
      const feeRate = (feeRateOverride != null) ? feeRateOverride
                : (this.__sessionFeeRate != null) ? this.__sessionFeeRate
                : await this.getEffectiveFeeRate();
      const txSize = 250;
      const fees = Math.round(txSize * (feeRate * 1e8) / 1000);
      const total = Math.round(specificUtxo.amount * 1e8);
      const change = total - target - fees;

      if (change < 0) throw new Error(getTranslation('messaging.insufficient_funds', 'Insufficient funds'));

      const { bitcoin } = await getBitcoinLibraries();
      const psbt = new bitcoin.Psbt({ network: NITO_NETWORK });
      psbt.setVersion(2);

      const scriptBuffer = Buffer.from(specificUtxo.scriptPubKey, 'hex');
      psbt.addInput({
        hash: specificUtxo.txid,
        index: specificUtxo.vout,
        witnessUtxo: { script: scriptBuffer, value: total }
      });

      psbt.addOutput({ address: toAddress, value: target });

      if (opReturnData) {
        const dataBuffer = Buffer.from(opReturnData, 'utf8');
        if (dataBuffer.length > 75) {
          throw new Error(getTranslation('messaging.opreturn_data_too_large', 'OP_RETURN data too large'));
        }

        const opReturnScript = bitcoin.script.compile([
          bitcoin.opcodes.OP_RETURN,
          dataBuffer
        ]);

        psbt.addOutput({ script: opReturnScript, value: 0 });
      }

      if (change > 294) {
        psbt.addOutput({ address: messagingState.bech32Address, value: change });
      }

      const walletKeyPair = await getWalletKeyPair();
      const walletPublicKey = await getWalletPublicKey();
      const signer = {
        network: walletKeyPair.network,
        privateKey: walletKeyPair.privateKey,
        publicKey: walletPublicKey,
        sign: (hash) => Buffer.from(walletKeyPair.sign(hash))
      };

      psbt.signInput(0, signer, [bitcoin.Transaction.SIGHASH_ALL]);
      psbt.finalizeAllInputs();

      const tx = psbt.extractTransaction();
      return tx.toHex();

    } catch (error) {
      console.error('[MESSAGING] OP_RETURN transaction creation error:', error);
      throw error;
    }
  }

  // === UTXO PREPARATION ===
  async prepareUtxosForMessage(chunksNeeded, feeRateOverride) {
    console.log(`[MESSAGING] Preparing ${chunksNeeded} optimized UTXOs for messaging...`);

    let availableUtxos = await this.getAvailableUtxos(messagingState.bech32Address);
    availableUtxos = availableUtxos.filter(utxo => utxo.amount >= 0.000003);
    if (availableUtxos.length === 0) {
      throw new Error('No UTXOs available for preparation');
    }

    const estimatedInputs = 1;
    const estimatedOutputs = chunksNeeded + 1;
    const estimatedTxSize = (estimatedInputs * 148) + (estimatedOutputs * 34) + 10;

    console.log(`[MESSAGING] Estimated transaction: ${estimatedTxSize} bytes for ${chunksNeeded} UTXOs`);

    const feeRate = (feeRateOverride != null) ? feeRateOverride
                : (this.__sessionFeeRate != null) ? this.__sessionFeeRate
                : await this.getEffectiveFeeRate();
    const preparationFeesInSatoshis = Math.round(estimatedTxSize * (feeRate * 1e8) / 1000);
    const preparationFeeRate = preparationFeesInSatoshis / 1e8;

    console.log(`[MESSAGING] Split preparation fees: ${preparationFeesInSatoshis} satoshis (${preparationFeeRate.toFixed(8)} NITO)`);

    const perChunkVBytes = 250;
    const perChunkFeesSat = Math.ceil(perChunkVBytes * ((feeRate * 1e8) / 1000));
    const perChunkFeesCoin = perChunkFeesSat / 1e8;
    console.log(`[MESSAGING] Estimated fees per chunk: ${perChunkFeesSat} satoshis (${perChunkFeesCoin.toFixed(8)} NITO)`);

    const amountPerUtxo = (MESSAGING_CONFIG.MESSAGE_FEE + perChunkFeesCoin) * 1.2;
    console.log(`[MESSAGING] Adaptive UTXOs: ${amountPerUtxo.toFixed(8)} NITO`);

    const totalNeeded = chunksNeeded * amountPerUtxo;

    const biggestUtxo = availableUtxos[0];
    if (biggestUtxo.amount < totalNeeded) {
      throw new Error(`Insufficient UTXO. Required: ${totalNeeded}, Available: ${biggestUtxo.amount}`);
    }

    console.log(`[MESSAGING] Creating ${chunksNeeded} UTXOs of ${amountPerUtxo} NITO each`);

    const { bitcoin } = await getBitcoinLibraries();
    const splitPsbt = new bitcoin.Psbt({ network: NITO_NETWORK });
    splitPsbt.setVersion(2);

    const scriptBuffer = Buffer.from(biggestUtxo.scriptPubKey, 'hex');
    const total = Math.round(biggestUtxo.amount * 1e8);

    splitPsbt.addInput({
      hash: biggestUtxo.txid,
      index: biggestUtxo.vout,
      witnessUtxo: { script: scriptBuffer, value: total }
    });

    const outputAmount = Math.round(amountPerUtxo * 1e8);
    for (let i = 0; i < chunksNeeded; i++) {
      splitPsbt.addOutput({ address: messagingState.bech32Address, value: outputAmount });
    }

    const usedAmount = chunksNeeded * outputAmount;
    const fees = Math.round(preparationFeeRate * 1e8);
    const change = total - usedAmount - fees;

    if (change > 294) {
      splitPsbt.addOutput({ address: messagingState.bech32Address, value: change });
    }

    const walletKeyPair = await getWalletKeyPair();
    const walletPublicKey = await getWalletPublicKey();
    const signer = {
      network: walletKeyPair.network,
      privateKey: walletKeyPair.privateKey,
      publicKey: walletPublicKey,
      sign: (hash) => Buffer.from(walletKeyPair.sign(hash))
    };

    splitPsbt.signInput(0, signer, [bitcoin.Transaction.SIGHASH_ALL]);
    splitPsbt.finalizeAllInputs();

    const tx = splitPsbt.extractTransaction();
    const txid = await window.rpc('sendrawtransaction', [tx.toHex()]);

    console.log(`[MESSAGING] UTXOs prepared, TXID: ${txid}`);

    createMessageProgressIndicator();

    console.log('[MESSAGING] Waiting for new UTXOs...');

    const MAX_WAIT_TIME = 3600000;
    const CHECK_INTERVAL = 6000;
    const EXPECTED_BLOCK_TIME = 120000;

    let elapsedTime = 0;
    let found = false;

    while (elapsedTime < MAX_WAIT_TIME && !found) {
      const progressBasedOnTime = Math.min(50, (elapsedTime / 60000) * 50);
      updateMessageProgress(
        progressBasedOnTime,
        100,
        getTranslation('progress_indicators.preparing_utxos_percentage', 'Preparing UTXOs: {{percentage}}%', { percentage: Math.round(progressBasedOnTime) })
      );
      console.log(`[MESSAGING] Waiting ${Math.round(elapsedTime/1000)}s - Progress: ${Math.round(progressBasedOnTime)}%`);

      await this.sleep(CHECK_INTERVAL);
      elapsedTime += CHECK_INTERVAL;

      const specificUtxos = await this.getSpecificTransactionUtxos(txid);

      if (specificUtxos.length >= chunksNeeded) {
        console.log(`[MESSAGING] ${specificUtxos.length} optimized specific UTXOs available!`);
        found = true;
        updateMessageProgress(50, 100, getTranslation('progress_indicators.utxos_ready', 'UTXOs ready'));
        await this.sleep(1000);
        return txid;
      }

      if (elapsedTime > EXPECTED_BLOCK_TIME && elapsedTime < EXPECTED_BLOCK_TIME + CHECK_INTERVAL) {
        console.log('[MESSAGING] Block slower than expected, extended waiting...');
      }

      if (elapsedTime % 300000 === 0 && elapsedTime > 0) {
        console.log(`[MESSAGING] Waiting in progress: ${Math.round(elapsedTime/60000)} minutes elapsed`);
      }
    }

    if (!found) {
      throw new Error(`Timeout: new UTXOs not confirmed after 60 minutes`);
    }
  }

  // === GET SPECIFIC TRANSACTION UTXOS ===
  async getSpecificTransactionUtxos(txid) {
    try {
      const tx = await window.rpc('getrawtransaction', [txid, true]);

      if (!tx.confirmations || tx.confirmations < 1) {
        return [];
      }

      const utxos = [];
      for (let i = 0; i < tx.vout.length; i++) {
        const output = tx.vout[i];
        if (output.scriptPubKey &&
            output.scriptPubKey.address === messagingState.bech32Address &&
            output.value >= MESSAGING_CONFIG.MESSAGE_FEE * 2) {

          utxos.push({
            txid: txid,
            vout: i,
            amount: output.value,
            scriptPubKey: output.scriptPubKey.hex,
            id: `${txid}:${i}`
          });
        }
      }

      return utxos;
    } catch (error) {
      console.warn(`[MESSAGING] Error checking specific UTXOs ${txid}:`, error.message);
      return [];
    }
  }

  // === MAIN SEND MESSAGE FUNCTION ===
  async sendMessage(message, recipientBech32Address) {
    if (window.isOperationActive && window.isOperationActive('send_message')) {
      throw new Error(getTranslation('messaging.sending_in_progress', 'Message sending already in progress'));
    }

    if (window.startOperation) window.startOperation('send_message');

    try {
      this.checkInitialized();

      createMessageProgressIndicator();
      updateMessageProgress(0, 100, getTranslation('messaging.initializing', 'Initializing'));

      const sessionFeeRate = await this.getEffectiveFeeRate();
      this.__sessionFeeRate = sessionFeeRate;

      const encryptedMessage = await this.encryptMessage(message, recipientBech32Address);
      const chunks = this.splitIntoChunks(encryptedMessage, MESSAGING_CONFIG.CHUNK_SIZE);
      const messageId = JSON.parse(encryptedMessage).messageId;

      let availableUtxos = await this.getFilteredAvailableUtxos(this.__sessionFeeRate);

      if (availableUtxos.length < chunks.length) {
        const missingCount = chunks.length - availableUtxos.length;
        await this.prepareUtxosForMessage(missingCount, this.__sessionFeeRate);

        await this.sleep(3000);
        availableUtxos = await this.getFilteredAvailableUtxos(this.__sessionFeeRate);
      } else {
        updateMessageProgress(50, 100, getTranslation('messaging.ready_to_send', 'Ready to send'));
      }

      if (availableUtxos.length < chunks.length) {
        throw new Error(getTranslation('messaging.insufficient_utxos_no_conflict',
          'Insufficient UTXOs to send {{chunks}} chunks without conflict.', { chunks: chunks.length }));
      }

      return await this.executeMessageSending(chunks, availableUtxos, messageId, recipientBech32Address);

    } catch (error) {
      console.error("[MESSAGING] Message sending error:", error);
      throw error;
    } finally {
      closeMessageProgress();
      if (window.endOperation) window.endOperation('send_message');
    }
  }

  // === GET FILTERED AVAILABLE UTXOS ===
  async getFilteredAvailableUtxos(feeRateOverride) {
    let allUtxos = await this.getAvailableUtxos(messagingState.bech32Address);

    const adaptiveAmount = await this.computeAdaptiveChunkAmount((feeRateOverride != null) ? feeRateOverride : this.__sessionFeeRate);
    const adaptiveSats = Math.round(adaptiveAmount * 1e8);
    const minFundingSats = Math.floor(adaptiveSats * 0.98);
    const candidates = allUtxos.filter(u => Math.round(u.amount * 1e8) >= (minFundingSats - 1));

    const uniqueTxids = Array.from(new Set(candidates.map(u => u.txid)));
    const inboundSet = new Set();
    const BATCH = 15;

    for (let i = 0; i < uniqueTxids.length; i += BATCH) {
      const chunk = uniqueTxids.slice(i, i + BATCH);
      const results = await Promise.all(chunk.map(async (txid) => {
        try {
          const tx = await this.getTxDetailCached(txid);
          const hasMsg = (tx.vout || []).some(v => {
            const hex = v.scriptPubKey && v.scriptPubKey.hex;
            if (!hex) return false;
            const data = this.extractOpReturnData(hex);
            return !!(data && data.startsWith(MESSAGING_CONFIG.MESSAGE_PREFIX));
          });
          return { txid, inbound: !!hasMsg };
        } catch (e) {
          return { txid, inbound: false };
        }
      }));
      for (const r of results) { if (r.inbound) inboundSet.add(r.txid); }
      await this.sleepJitter(1, 300, uniqueTxids.length > 100);
    }

    const filtered = candidates.filter(u => !inboundSet.has(u.txid));

    return filtered;
  }

  // === EXECUTE MESSAGE SENDING ===
  async executeMessageSending(chunks, availableUtxos, messageId, recipientBech32Address) {
    const utxosToUse = availableUtxos.slice().sort((a,b) => a.amount - b.amount).slice(0, chunks.length);

    utxosToUse.forEach(utxo => this.markUtxoAsUsed(utxo.txid, utxo.vout));

    try {
      const preparedTransactions = [];

      for (let i = 0; i < chunks.length; i++) {
        const progress = 50 + Math.round((i / chunks.length) * 25);
        updateMessageProgress(progress, 100, getTranslation('messaging.preparing_chunks', 'Preparing chunks'));

        const opReturnData = `${MESSAGING_CONFIG.MESSAGE_PREFIX}${messageId}_${i}_${chunks.length}_${chunks[i]}`;
        const selectedUtxo = utxosToUse[i];

        const hex = await this.createOpReturnTransaction(
          recipientBech32Address,
          MESSAGING_CONFIG.MESSAGE_FEE,
          opReturnData,
          selectedUtxo
        );
        preparedTransactions.push({ chunkIndex: i, hex, utxo: selectedUtxo });
      }

      const results = [];
      for (let i = 0; i < preparedTransactions.length; i++) {
        const transaction = preparedTransactions[i];
        const progress = 75 + Math.round(((i + 1) / preparedTransactions.length) * 25);
        updateMessageProgress(
          progress,
          100,
          getTranslation('messaging.sending_chunk', 'Sending chunk {{current}}/{{total}}', { current: i + 1, total: preparedTransactions.length })
        );

        try {
          const txid = await handleError500WithRetry(async () => {
            return await window.rpc("sendrawtransaction", [transaction.hex]);
          });

          results.push({
            success: true,
            txid: txid,
            chunkIndex: transaction.chunkIndex,
            transaction: transaction
          });
        } catch (error) {
          console.error(`[MESSAGING] Chunk send error ${transaction.chunkIndex}:`, error);
          results.push({
            success: false,
            error: error.message,
            chunkIndex: transaction.chunkIndex,
            transaction: transaction
          });
        }
      }

      const successfulResults = results.filter(r => r.success);
      const transactions = successfulResults.map(r => r.txid);

      console.log(`[MESSAGING] Message sent successfully! Chunks: ${successfulResults.length}/${chunks.length}, Transactions:`, transactions);

      closeMessageProgress(3000);

      const lastTxid = transactions[transactions.length - 1];
      if (window.showSuccessPopup && lastTxid) {
        await window.showSuccessPopup(lastTxid);
      }

      return {
        success: true,
        messageId,
        transactions,
        chunks: successfulResults.length,
        totalChunks: chunks.length,
        totalCost: successfulResults.length * MESSAGING_CONFIG.MESSAGE_FEE,
        efficient: successfulResults.length === chunks.length,
        lastTxid: lastTxid
      };

    } finally {
      utxosToUse.forEach(utxo => this.releaseUtxo(utxo.txid, utxo.vout));
    }
  }

  // === MESSAGE SCANNING ===
  async scanInboxMessages() {
    if (window.isOperationActive && window.isOperationActive('scan_messages')) {
      while (window.isOperationActive && window.isOperationActive('scan_messages')) {
        await this.sleep(500);
      }
      return this.messageCache.get('lastScanResult') || [];
    }

    if (window.startOperation) window.startOperation('scan_messages');

    try {
      this.checkInitialized();

      const transactions = await this.getAddressTransactions(messagingState.bech32Address);
      const messages = new Map();

      for (const tx of transactions) {
        const opReturnData = tx.opReturnData;

        if (opReturnData && opReturnData.startsWith(MESSAGING_CONFIG.MESSAGE_PREFIX)) {
          const messageData = opReturnData.substring(MESSAGING_CONFIG.MESSAGE_PREFIX.length);
          const parts = messageData.split('_');

          if (parts.length < 4) {
            console.warn("[MESSAGING] Invalid chunk format:", messageData);
            continue;
          }

          const [messageId, chunkIndex, totalChunks, ...chunkDataParts] = parts;
          const chunkData = chunkDataParts.join('_');

          if (this.deletedMessages.has(messageId)) continue;

          if (!messages.has(messageId)) {
            messages.set(messageId, {
              id: messageId,
              chunks: new Map(),
              totalChunks: parseInt(totalChunks),
              timestamp: tx.time || Date.now() / 1000,
              txid: tx.txid,
              senderAddress: tx.senderAddress
            });
          }

          const message = messages.get(messageId);
          const chunkIdx = parseInt(chunkIndex);

          if (chunkIdx >= 0 && chunkIdx < message.totalChunks && !message.chunks.has(chunkIdx)) {
            message.chunks.set(chunkIdx, chunkData);
          }
        }
      }

      const completeMessages = [];
      for (const [messageId, messageData] of messages) {
        if (messageData.chunks.size === messageData.totalChunks) {
          try {
            const sortedChunks = [];
            for (let i = 0; i < messageData.totalChunks; i++) {
              if (!messageData.chunks.has(i)) {
                throw new Error(`Missing chunk at index ${i}`);
              }
              sortedChunks.push(messageData.chunks.get(i));
            }
            const encryptedMessage = sortedChunks.join('');

            // Check if message is for us before trying to decrypt
            try {
              const __env = JSON.parse(encryptedMessage);
              if (__env && __env.recipient && __env.recipient !== messagingState.bech32Address) {
                continue;
              }
            } catch (e) {}

            const decryptedMessage = await this.decryptMessage(encryptedMessage, messageData.senderAddress);
            completeMessages.push({
              id: messageId,
              content: decryptedMessage.content,
              sender: decryptedMessage.sender,
              timestamp: decryptedMessage.timestamp,
              status: 'unread',
              verified: decryptedMessage.verified,
              senderAddress: messageData.senderAddress
            });

          } catch (error) {
            if (error && error.message && /not for you/.test(error.message)) {
              continue;
            }

            console.error(`[MESSAGING] Message decryption error ${messageId}:`, error);

            let errorType = getTranslation('messaging.decryption_error_type', 'Decryption error');
            if (error.message.includes("GCM")) {
              errorType = getTranslation('messaging.corrupted_data', 'Corrupted data');
            } else if (error.message.includes("JSON")) {
              errorType = getTranslation('messaging.invalid_format', 'Invalid format');
            } else if (error.message.includes("not for you")) {
              errorType = getTranslation('messaging.message_not_for_you', 'Message not for you');
            } else if (error.message.includes("ECDH")) {
              errorType = getTranslation('messaging.cryptographic_error', 'Cryptographic error');
            }

            completeMessages.push({
              id: messageId,
              content: `[${getTranslation('messaging.unreadable_message', 'Unreadable message')} - ${errorType}: ${error.message}]`,
              sender: messageData.senderAddress,
              timestamp: messageData.timestamp,
              status: 'error',
              verified: false,
              senderAddress: messageData.senderAddress,
              errorDetails: error.message
            });
          }
        }
      }

      const sortedMessages = completeMessages.sort((a, b) => b.timestamp - a.timestamp);

      this.messageCache.set('lastScanResult', sortedMessages);

      return sortedMessages;
    } catch (error) {
      console.error('[MESSAGING] Message scan error:', error);
      throw error;
    } finally {
      if (window.endOperation) window.endOperation('scan_messages');
    }
  }

  // === BLOCKCHAIN SCANNING ===
  async getAddressTransactions(address) {
    try {
      const scan = await handleError500WithRetry(async () => {
        return await window.rpc("scantxoutset", ["start", [`addr(${address})`]]);
      });

      if (scan.unspents) {
        scan.unspents = scan.unspents.filter(u => u.amount <= MESSAGING_CONFIG.PROTECTION_LIMIT);
      }

      const transactions = [];
      const uniqueTxids = [...new Set(scan.unspents?.map(utxo => utxo.txid) || [])];

      let processed = 0;
      let totalAll = uniqueTxids.length;
      const BATCH_SIZE = 200;

      createMessageProgressIndicator();

      for (let i = 0; i < uniqueTxids.length; i += BATCH_SIZE) {
        const batch = uniqueTxids.slice(i, i + BATCH_SIZE);

        const MAX_RETRY = 20;
        let attempt = 0;
        let remaining = new Set(batch);
        const got = new Map();

        while (remaining.size > 0 && attempt < MAX_RETRY) {
          attempt++;

          const nowTxids = Array.from(remaining);
          const results = await Promise.all(nowTxids.map(async (txid) => {
            try {
              const txDetail = await handleError500WithRetry(async () => {
                return await window.rpc("getrawtransaction", [txid, true]);
              });

              let opReturnData = null;
              for (const output of txDetail.vout) {
                if (output.scriptPubKey && output.scriptPubKey.hex) {
                  const data = this.extractOpReturnData(output.scriptPubKey.hex);
                  if (data) { opReturnData = data; break; }
                }
              }

              let senderAddress = "unknown_sender";
              if (txDetail.vin && txDetail.vin.length > 0) {
                senderAddress = await this.getTransactionSenderAddress(txDetail.txid);
              }

              return {
                ok: true,
                txid: txDetail.txid,
                value: {
                  txid: txDetail.txid,
                  time: txDetail.time || txDetail.blocktime || Date.now() / 1000,
                  vout: txDetail.vout,
                  vin: txDetail.vin,
                  opReturnData,
                  senderAddress
                }
              };
            } catch (_) {
              return { ok: false, txid };
            }
          }));

          for (const r of results) {
            if (r.ok) {
              got.set(r.txid, r.value);
              remaining.delete(r.txid);
            }
          }

          const missing = remaining.size;
          if (missing > 0) {
            const delayMs = Math.min(4000, 200 * Math.pow(1.5, attempt)) + Math.floor(Math.random() * 250);
            await this.sleep(delayMs);
          }
        }

        if (remaining.size > 0) {
          while (remaining.size > 0) {
            const nowTxids = Array.from(remaining);
            for (const txid of nowTxids) {
              try {
                const txDetail = await handleError500WithRetry(async () => {
                  return await window.rpc("getrawtransaction", [txid, true]);
                });
                let opReturnData = null;
                for (const output of txDetail.vout) {
                  if (output.scriptPubKey?.hex) {
                    const data = this.extractOpReturnData(output.scriptPubKey.hex);
                    if (data) { opReturnData = data; break; }
                  }
                }
                let senderAddress = await this.getTransactionSenderAddress(txDetail.txid);
                got.set(txid, {
                  txid: txDetail.txid,
                  time: txDetail.time || txDetail.blocktime || Date.now() / 1000,
                  vout: txDetail.vout,
                  vin: txDetail.vin,
                  opReturnData,
                  senderAddress
                });
                remaining.delete(txid);
              } catch (_) {}
            }
            if (remaining.size > 0) {
              await this.sleep(500);
            }
          }
        }

        const validResults = Array.from(got.values());
        transactions.push(...validResults);

        processed += batch.length;
        showScanProgress(processed, totalAll);

        if (i + BATCH_SIZE < uniqueTxids.length) {
          await this.sleep(100);
        }
      }

      closeMessageProgress(1000);
      return transactions;

    } catch (error) {
      console.error('[MESSAGING] Transaction retrieval error:', error);
      return [];
    }
  }

  // === UTILITY FUNCTIONS ===
  extractOpReturnData(scriptHex) {
    try {
      const script = Buffer.from(scriptHex, "hex");

      if (script.length > 2 && script[0] === 0x6a) {
        let dataStart = 1;
        let dataLength = 0;

        if (script[1] <= 75) {
          dataLength = script[1];
          dataStart = 2;
        } else if (script[1] === 0x4c) {
          dataLength = script[2];
          dataStart = 3;
        } else if (script[1] === 0x4d) {
          dataLength = script[2] + (script[3] << 8);
          dataStart = 4;
        }

        if (script.length >= dataStart + dataLength && dataLength > 0) {
          const data = script.slice(dataStart, dataStart + dataLength).toString("utf8");
          return data;
        }
      }

      return null;
    } catch (error) {
      console.error("[MESSAGING] OP_RETURN decode error:", error);
      return null;
    }
  }

  async getTransactionSenderAddress(txid) {
    try {
      const tx = await handleError500WithRetry(async () => {
        return await window.rpc('getrawtransaction', [txid, true]);
      });

      if (tx.vin && tx.vin.length > 0) {
        const firstInput = tx.vin[0];
        if (firstInput.txid && firstInput.vout !== undefined) {
          const prevTx = await handleError500WithRetry(async () => {
            return await window.rpc('getrawtransaction', [firstInput.txid, true]);
          });
          const prevOutput = prevTx.vout[firstInput.vout];

          if (prevOutput.scriptPubKey && prevOutput.scriptPubKey.addresses) {
            return prevOutput.scriptPubKey.addresses[0];
          }
          if (prevOutput.scriptPubKey && prevOutput.scriptPubKey.address) {
            return prevOutput.scriptPubKey.address;
          }
        }
      }

      return "unknown_sender";
    } catch (error) {
      return "unknown_sender";
    }
  }

  splitIntoChunks(data, chunkSize) {
    const chunks = [];
    for (let i = 0; i < data.length; i += chunkSize) {
      chunks.push(data.slice(i, i + chunkSize));
    }
    return chunks;
  }

  generateMessageId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// === GLOBAL MESSAGING INSTANCE ===
const messaging = new NitoMessaging();

// === INITIALIZATION SYSTEM ===
let initializationAttempts = 0;
const MAX_INITIALIZATION_ATTEMPTS = 5;

async function initializeMessagingWhenReady() {
  if (messagingInitialized || initializationInProgress) {
    return;
  }

  if (initializationAttempts >= MAX_INITIALIZATION_ATTEMPTS) {
    return;
  }

  initializationInProgress = true;
  initializationAttempts++;

  try {
    const walletInfo = await getWalletInfo();
    if (walletInfo.isReady) {
      const initialized = await messaging.initialize();
      if (initialized) {
        messagingInitialized = true;
        setupMessagingInterface();
        return;
      }
    }

    if (initializationAttempts < MAX_INITIALIZATION_ATTEMPTS) {
      setTimeout(() => {
        initializationInProgress = false;
        initializeMessagingWhenReady();
      }, 3000);
    } else {
      initializationInProgress = false;
    }
  } catch (error) {
    console.error('[MESSAGING] Messaging initialization error:', error);
    initializationInProgress = false;

    if (initializationAttempts < MAX_INITIALIZATION_ATTEMPTS) {
      setTimeout(() => {
        initializeMessagingWhenReady();
      }, 5000);
    }
  }
}

let walletImportListenerAdded = false;

if (!walletImportListenerAdded) {
  eventBus.on(EVENTS.WALLET_IMPORTED, () => {
    setTimeout(() => {
      initializeMessagingWhenReady();
    }, 1000);
  });
  walletImportListenerAdded = true;
}

// === UI SETUP ===
function setupMessagingInterface() {
  if (messagingState.interfaceSetup) {
    return;
  }

  messagingState.interfaceSetup = true;

  const elementsToClean = [
    'publishPubkeyButton',
    'sendMessageButton',
    'confirmSendButton',
    'cancelSendButton',
    'clearMessageButton',
    'refreshMessagesButton',
    'messageInput'
  ];

  elementsToClean.forEach(id => {
    const element = document.getElementById(id);
    if (element) {
      const newElement = element.cloneNode(true);
      element.parentNode.replaceChild(newElement, element);
    }
  });

  setupMessagingButtons();
}

function setupMessagingButtons() {
  if (buttonListenersSetup) {
    return;
  }

  buttonListenersSetup = true;

  const publishButton = document.getElementById('publishPubkeyButton');
  if (publishButton) {
    publishButton.addEventListener('click', async () => {
      if (window.isOperationActive && window.isOperationActive('publish_pubkey')) {
        alert(getTranslation('messaging.publication_in_progress', 'Publication already in progress'));
        return;
      }

      try {
        if (window.showLoading) window.showLoading(getTranslation('messaging.publishing_pubkey', 'Publishing public key...'));
        const result = await messaging.publishPublicKey();
      } catch (error) {
        alert(`${getTranslation('errors.error_details', 'Error')}: ${error.message}`);
      } finally {
        if (window.hideLoading) window.hideLoading();
      }
    });
  }

  const sendButton = document.getElementById('sendMessageButton');
  if (sendButton) {
    sendButton.addEventListener('click', () => {
      const message = document.getElementById('messageInput')?.value.trim();
      if (!message) {
        alert(getTranslation('messaging.enter_message', 'Enter a message'));
        return;
      }
      if (message.length > MESSAGING_CONFIG.MAX_MESSAGE_LENGTH) {
        alert(`${getTranslation('messaging.message_too_long', 'Message too long')}: ${message.length}/${MESSAGING_CONFIG.MAX_MESSAGE_LENGTH} ${getTranslation('messaging.characters', 'characters')}`);
        return;
      }

      document.getElementById('sendMessageForm').style.display = 'block';
    });
  }

  const confirmButton = document.getElementById('confirmSendButton');
  if (confirmButton) {
    confirmButton.addEventListener('click', async () => {
      if (window.isOperationActive && window.isOperationActive('send_message')) {
        alert(getTranslation('messaging.sending_already_in_progress', 'Sending already in progress...'));
        return;
      }

      try {
        const message = document.getElementById('messageInput').value.trim();
        const recipient = document.getElementById('recipientAddress').value.trim();

        if (!message || !recipient) {
          alert(getTranslation('messaging.fill_all_fields', 'Fill all fields'));
          return;
        }
        if (!recipient.startsWith('nito1')) {
          alert(getTranslation('messaging.invalid_bech32_address', 'Invalid bech32 address'));
          return;
        }

        const result = await messaging.sendMessage(message, recipient);

        if (result.efficient) {
          console.log(`[MESSAGING] Message sent successfully! ID: ${result.messageId}, Transactions: ${result.chunks}/${result.totalChunks}, Cost: ${result.totalCost.toFixed(8)} NITO`);
        } else {
          alert(`${getTranslation('messaging.message_sent_partially', 'Message sent partially')}: ${result.messageId}, ${result.chunks}/${result.totalChunks} chunks, ${getTranslation('messaging.cost', 'cost')}: ${result.totalCost.toFixed(8)} NITO`);
        }

        document.getElementById('messageInput').value = '';
        document.getElementById('recipientAddress').value = '';
        document.getElementById('sendMessageForm').style.display = 'none';
        updateCharCounter();
      } catch (error) {
        alert(`${getTranslation('errors.error_details', 'Error')}: ${error.message}`);
      }
    });
  }

  const cancelButton = document.getElementById('cancelSendButton');
  if (cancelButton) {
    cancelButton.addEventListener('click', () => {
      document.getElementById('sendMessageForm').style.display = 'none';
    });
  }

  const clearButton = document.getElementById('clearMessageButton');
  if (clearButton) {
    clearButton.addEventListener('click', () => {
      document.getElementById('messageInput').value = '';
      document.getElementById('sendMessageForm').style.display = 'none';
      updateCharCounter();
    });
  }

  const refreshButton = document.getElementById('refreshMessagesButton');
  if (refreshButton) {
    refreshButton.addEventListener('click', async () => {
      if (window.isOperationActive && window.isOperationActive('refresh_messages')) {
        return;
      }

      if (window.startOperation) window.startOperation('refresh_messages');

      try {
        const originalText = refreshButton.textContent;
        const originalDisabled = refreshButton.disabled;

        refreshButton.disabled = true;
        refreshButton.textContent = getTranslation('messaging.refreshing_messages', 'Refreshing...');

        const messages = await messaging.scanInboxMessages();
        displayMessages(messages);
        updateUnreadCounter(messages.filter(m => m.status === 'unread').length);

        refreshButton.disabled = originalDisabled;
        refreshButton.textContent = originalText;

      } catch (error) {
        alert(`${getTranslation('errors.error_details', 'Error')}: ${error.message}`);
        refreshButton.disabled = false;
        refreshButton.textContent = getTranslation('encrypted_messaging.refresh_messages', 'Refresh messages');
      } finally {
        if (window.endOperation) window.endOperation('refresh_messages');
      }
    });
  }

  const messageInput = document.getElementById('messageInput');
  if (messageInput) {
    messageInput.addEventListener('input', updateCharCounter);
  }

  updateCharCounter();
}

// === UI FUNCTIONS ===
function updateCharCounter() {
  const input = document.getElementById('messageInput');
  const counter = document.getElementById('messageCharCounter');
  if (input && counter) {
    const length = input.value.length;
    counter.textContent = `${length}/${MESSAGING_CONFIG.MAX_MESSAGE_LENGTH}`;
    counter.className = length > MESSAGING_CONFIG.MAX_MESSAGE_LENGTH ? 'char-counter over-limit' : 'char-counter';
  }
}

function displayMessages(messages) {
  const list = document.getElementById('messageList');
  if (!list) return;

  if (!messages || !messages.length) {
    const noMessagesText = getTranslation('messaging.no_messages_received', 'No messages received');
    list.innerHTML = `<div class="message-item">${noMessagesText}</div>`;
    list.style.display = 'block';
    return;
  }

  const inboxItems = messages.map(m => ({
    id: m.id,
    senderBech32: m.sender || m.senderAddress || 'unknown_sender',
    time: Math.floor((m.timestamp || Date.now()) / 1000),
    body: m.content || ''
  }));

  renderInboxEmailStyle(inboxItems);
}

function renderInboxEmailStyle(inboxItems) {
  const list = document.getElementById('messageList');
  if (!list) return;

  if (!inboxItems || !inboxItems.length) {
    const noMessagesText = getTranslation('messaging.no_messages_received', 'No messages received');
    list.innerHTML = `<div class="message-item">${noMessagesText}</div>`;
    list.style.display = 'block';
    return;
  }

  // Créer les éléments DOM de manière sécurisée pour éviter les problèmes d'échappement
  list.innerHTML = '';

  inboxItems.forEach(item => {
    const timestamp = item.time ? new Date(item.time * 1000).toLocaleString() : getTranslation('messaging.unknown_date', 'Unknown date');
    const senderDisplay = item.senderBech32 || getTranslation('messaging.unknown_sender', 'Unknown sender');

    const rowDiv = document.createElement('div');
    rowDiv.className = 'inbox-row';

    const contentDiv = document.createElement('div');
    const titleDiv = document.createElement('div');
    titleDiv.className = 'inbox-title';
    titleDiv.textContent = senderDisplay;
    contentDiv.appendChild(titleDiv);

    const timeDiv = document.createElement('div');
    timeDiv.className = 'inbox-time';
    timeDiv.textContent = timestamp;

    rowDiv.appendChild(contentDiv);
    rowDiv.appendChild(timeDiv);

    // Ajouter l'event listener de manière sécurisée
    rowDiv.addEventListener('click', () => {
      window.showMessageModal(item.id, senderDisplay, item.body || '');
    });

    list.appendChild(rowDiv);
  });

  list.style.display = 'block';
}

function updateUnreadCounter(count) {
  const unreadDiv = document.getElementById('unreadMessages');
  const countSpan = document.getElementById('unreadCount');
  if (unreadDiv && countSpan) {
    countSpan.textContent = count;
    unreadDiv.style.display = count > 0 ? 'block' : 'none';
  }
}

// === UI FUNCTIONS EXPORT ===
export const MessagingUI = {
  displayMessages,
  renderInboxEmailStyle,
  updateUnreadCounter,
  updateCharCounter
};

// === GLOBAL COMPATIBILITY ===
export { messaging };
if (typeof window !== 'undefined') {
  window.messaging = messaging;
  window.MessagingUI = MessagingUI;
  window.renderInboxEmailStyle = renderInboxEmailStyle;
  window.showMessageModal = showMessageModal;
}

// === INITIALIZATION ===
let domInitialized = false;

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    if (!domInitialized) {
      domInitialized = true;
      initializeMessagingWhenReady();
    }
  });
} else {
  if (!domInitialized) {
    domInitialized = true;
    initializeMessagingWhenReady();
  }
}
