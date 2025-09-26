// Encrypted Messaging System for NITO Wallet 
// Handles encrypted message sending, receiving, and public key management

import { MESSAGING_CONFIG, NITO_NETWORK, ELEMENT_IDS, NODE_CONFIG, FEATURE_FLAGS } from './config.js';
import { eventBus, EVENTS } from './events.js';
import { waitForLibraries } from './vendor.js';

// === TRANSLATION HELPER ===
function getTranslation(key, fallback, params = {}) {
  const t = (window.i18next && typeof window.i18next.t === 'function') 
    ? window.i18next.t 
    : () => fallback || key;
  return t(key, { ...params, defaultValue: fallback });
}

// === OPERATIONS TRACKING ===
const OPERATION_TYPES = {
  PUBLISH_PUBKEY: 'publish_pubkey',
  SEND_MESSAGE: 'send_message',
  SCAN_MESSAGES: 'scan_messages',
  REFRESH_MESSAGES: 'refresh_messages'
};

const activeOperations = new Set();

function startOperation(operationType) {
  activeOperations.add(operationType);
  console.log(`[MESSAGING] Started: ${operationType}`);
}

function endOperation(operationType) {
  activeOperations.delete(operationType);
  console.log(`[MESSAGING] Ended: ${operationType}`);
}

function isOperationActive(operationType = null) {
  if (operationType) {
    return activeOperations.has(operationType);
  }
  return activeOperations.size > 0;
}

// === ERROR HANDLING WITH RETRY ===
async function handleError500WithRetry(operation, maxRetries = 3) {
  let attempt = 0;
  
  while (attempt < maxRetries) {
    try {
      return await operation();
    } catch (error) {
      const errorMsg = String(error.message || error);
      
      if (errorMsg.includes('500') || errorMsg.includes('Internal Server Error')) {
        attempt++;
        console.warn(`[MESSAGING] 500 Error (attempt ${attempt}/${maxRetries}):`, errorMsg);
        
        if (attempt < maxRetries) {
          console.log(`[MESSAGING] Waiting ${NODE_CONFIG.ERROR_500_DELAY}ms before retry...`);
          await new Promise(resolve => setTimeout(resolve, NODE_CONFIG.ERROR_500_DELAY));
          continue;
        } else {
          console.error(`[MESSAGING] Operation failed after ${maxRetries} attempts`);
        }
      }
      
      throw error;
    }
  }
}

// === SAFE LIBRARY ACCESS ===
async function getBitcoinLibraries() {
  await waitForLibraries();

  if (!window.bitcoin) {
    throw new Error('Bitcoin libraries not available');
  }

  return {
    bitcoin: window.bitcoin
  };
}

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
      
      // Log addresses if enabled
      if (FEATURE_FLAGS.LOG_ADDRESSES) {
        console.log('[MESSAGING] Wallet addresses:', {
          bech32: walletInfoCache.addresses.bech32,
          taproot: walletInfoCache.addresses.taproot,
          legacy: walletInfoCache.addresses.legacy,
          p2sh: walletInfoCache.addresses.p2sh
        });
      }
      
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

// === MAIN MESSAGING CLASS WITH ENHANCED ERROR HANDLING ===
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
    console.log(`[MESSAGING] UTXO réservé: ${utxoId}`);
  }

  releaseUtxo(txid, vout) {
    const utxoId = `${txid}:${vout}`;
    this.usedUtxos.delete(utxoId);
    console.log(`[MESSAGING] UTXO libéré: ${utxoId}`);
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

      console.log(`[MESSAGING] UTXOs viables: ${viableUtxos.length}, Disponibles: ${availableUtxos.length}`);
      if (availableUtxos.length > 0) {
        console.log(`[MESSAGING] Plus gros UTXO disponible: ${availableUtxos[0].amount} NITO`);
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
      console.log('[MESSAGING] Messagerie initialisée pour:', messagingState.bech32Address);
      return true;
    }
    return false;
  }

  checkInitialized() {
    if (!messagingState.isInitialized) {
      throw new Error('Wallet not initialized');
    }
  }

  // === CRYPTOGRAPHY ===
  async deriveSharedKey(myPrivateKey, theirPublicKey) {
    try {
      console.log('[MESSAGING]', getTranslation('messaging.encryption_ecdh_for', 'Calcul ECDH avec noble-secp256k1...'));

      if (!myPrivateKey || !theirPublicKey) {
        throw new Error('Clés manquantes pour ECDH');
      }

      if (!window.secp256k1) {
        throw new Error('secp256k1 library not available');
      }

      const privateKeyHex = Buffer.from(myPrivateKey).toString('hex');
      const publicKeyHex = Buffer.from(theirPublicKey).toString('hex');

      if (!window.secp256k1.utils.isValidPrivateKey(privateKeyHex)) {
        throw new Error('Clé privée invalide');
      }

      const sharedPoint = window.secp256k1.getSharedSecret(privateKeyHex, publicKeyHex, true);
      const hashBuffer = await crypto.subtle.digest('SHA-256', sharedPoint);
      const derivedKey = new Uint8Array(hashBuffer);

      console.log('[MESSAGING] Clé ECDH dérivée avec succès');
      return derivedKey;

    } catch (error) {
      console.error('[MESSAGING] Erreur ECDH:', error);
      throw new Error(`Erreur dérivation clé partagée: ${error.message}`);
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

      console.log('[MESSAGING] Chiffrement AES-GCM réussi');
      return base64Result;

    } catch (error) {
      console.error('[MESSAGING] Erreur chiffrement AES:', error);
      throw new Error(`Erreur chiffrement: ${error.message}`);
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

      console.log('[MESSAGING] Déchiffrement AES-GCM réussi');
      return result;

    } catch (error) {
      console.error('[MESSAGING] Erreur déchiffrement AES:', error);
      throw new Error(`Erreur déchiffrement: ${error.message}`);
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
    if (isOperationActive(OPERATION_TYPES.PUBLISH_PUBKEY)) {
      throw new Error('Publication déjà en cours');
    }
    
    startOperation(OPERATION_TYPES.PUBLISH_PUBKEY);
    
    try {
      this.checkInitialized();

      const publicKey = await getWalletPublicKey();
      const publicKeyHex = Buffer.from(publicKey).toString('hex');
      const opReturnData = `NITOPUB:${publicKeyHex}`;

      console.log('[MESSAGING] Publication clé publique...');

      let availableUtxos = await this.getAvailableUtxos(messagingState.bech32Address);
      availableUtxos = availableUtxos.filter(utxo => utxo.amount >= 0.000003);
      if (availableUtxos.length === 0) {
        const errorMsg = getTranslation('messaging.no_utxo_for_pubkey', 'Aucun UTXO disponible pour publier la clé publique');
        throw new Error(errorMsg);
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

      const successMsg = getTranslation('messaging.pubkey_published', 'Clé publique publiée, TXID: {{txid}}', { txid });
      console.log('[MESSAGING]', successMsg);

      if (window.showSuccessPopup) {
        await window.showSuccessPopup(txid);
      }

      return { success: true, txid, publicKey: publicKeyHex };
    } catch (error) {
      console.error('[MESSAGING] Erreur publication clé publique:', error);
      const errorMsg = getTranslation('messaging.publication_error', 'Erreur publication: {{error}}', { error: error.message });
      throw new Error(errorMsg);
    } finally {
      endOperation(OPERATION_TYPES.PUBLISH_PUBKEY);
    }
  }

  async findPublicKey(bech32Address) {
    try {
      if (!bech32Address || bech32Address === "null" || bech32Address === "unknown_sender") {
        const logMsg = getTranslation('messaging.no_address_or_unknown', 'Adresse invalide ou inconnue: {{address}}', { address: bech32Address });
        console.log('[MESSAGING]', logMsg);
        return null;
      }

      const searchMsg = getTranslation('messaging.searching_pubkey_for', 'Recherche clé publique pour: {{address}}', { address: bech32Address });
      console.log('[MESSAGING]', searchMsg);

      const scan = await handleError500WithRetry(async () => {
        return await window.rpc("scantxoutset", ["start", [`addr(${bech32Address})`]]);
      });

      if (!scan.unspents) {
        const notFoundMsg = getTranslation('messaging.no_transactions_found', 'Aucune transaction trouvée pour: {{address}}', { address: bech32Address });
        console.log('[MESSAGING]', notFoundMsg);
        return null;
      }

      const analyzeMsg = getTranslation('messaging.analyzing_transactions', 'Analyse de {{count}} UTXOs pour trouver la clé publique', { count: scan.unspents.length });
      console.log('[MESSAGING]', analyzeMsg);

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
                  const foundMsg = getTranslation('messaging.pubkey_found_validated_for', 'CLÉ PUBLIQUE TROUVÉE ET VALIDÉE pour: {{address}}', { address: bech32Address });
                  console.log('[MESSAGING]', foundMsg);
                  return publicKeyBuffer;
                }
              }
            }
          }
        } catch (e) {
          console.warn(`[MESSAGING] Erreur analyse transaction ${utxo.txid}:`, e.message);
        }
      }

      const notFoundMsg = getTranslation('messaging.no_pubkey_found_for', 'Aucune clé publique trouvée pour: {{address}}', { address: bech32Address });
      console.log('[MESSAGING]', notFoundMsg);
      return null;
    } catch (error) {
      console.error("[MESSAGING] Erreur recherche clé publique:", error);
      throw error;
    } finally {
      this.__sessionFeeRate = null;
    }
  }

  // === MESSAGE ENCRYPTION/DECRYPTION ===
  async encryptMessage(message, recipientBech32Address) {
    this.checkInitialized();

    try {
      const encryptMsg = getTranslation('messaging.encryption_ecdh_for', 'Chiffrement ECDH pour: {{address}}', { address: recipientBech32Address });
      console.log('[MESSAGING]', encryptMsg);

      const recipientPublicKey = await this.findPublicKey(recipientBech32Address);
      if (!recipientPublicKey) {
        throw new Error('Clé publique du destinataire introuvable. Le destinataire doit d\'abord publier sa clé publique.');
      }

      console.log("[MESSAGING] Clé publique destinataire trouvée");

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

      const successMsg = getTranslation('messaging.encryption_successful', 'Message chiffré avec ECDH + AES-GCM');
      console.log('[MESSAGING]', successMsg);
      return JSON.stringify(finalMessage);

    } catch (error) {
      console.error('[MESSAGING] Erreur chiffrement ECDH:', error);
      throw error;
    }
  }

  async decryptMessage(encryptedMessage, senderAddress) {
    this.checkInitialized();

    try {
      const decryptMsg = getTranslation('messaging.decryption_ecdh_completed', 'Déchiffrement ECDH pour: {{address}}', { address: messagingState.bech32Address });
      console.log('[MESSAGING]', decryptMsg);

      if (!encryptedMessage || typeof encryptedMessage !== 'string') {
        throw new Error("Message vide ou invalide");
      }

      let messageEnvelope;
      try {
        messageEnvelope = JSON.parse(encryptedMessage);
      } catch (e) {
        throw new Error("Format de message invalide");
      }

      if (messageEnvelope.recipient !== messagingState.bech32Address) {
        throw new Error("Ce message ne vous est pas destiné");
      }

      let senderPublicKey;
      if (messageEnvelope.senderPublicKey) {
        senderPublicKey = Buffer.from(messageEnvelope.senderPublicKey, 'hex');
        console.log("[MESSAGING] Clé publique incluse utilisée - pas de scan blockchain");
      } else {
        senderPublicKey = await this.findPublicKey(messageEnvelope.sender);
        if (!senderPublicKey) {
          throw new Error("Impossible de trouver la clé publique de l'expéditeur");
        }
      }

      console.log("[MESSAGING] Clé publique expéditeur trouvée");

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
        throw new Error("Erreur parsing message déchiffré");
      }

      const expectedSignature = await this.hashMessage(
        decryptedMessage.messageId +
        decryptedMessage.timestamp +
        decryptedMessage.sender
      );
      const verified = expectedSignature === messageEnvelope.signature;

      const completedMsg = getTranslation('messaging.decryption_ecdh_completed', 'Déchiffrement ECDH terminé, message vérifié: {{verified}}', { verified });
      console.log('[MESSAGING]', completedMsg);

      return {
        ...decryptedMessage,
        verified
      };

    } catch (error) {
      console.error("[MESSAGING] Erreur déchiffrement ECDH:", error);
      throw error;
    }
  }

  // === TRANSACTION CREATION ===
  async createOpReturnTransaction(toAddress, amount, opReturnData, specificUtxo, feeRateOverride = null) {
    this.checkInitialized();

    try {
      if (!specificUtxo) {
        throw new Error("UTXO spécifique requis");
      }

      const target = Math.round(amount * 1e8);
      const feeRate = (feeRateOverride != null) ? feeRateOverride
                : (this.__sessionFeeRate != null) ? this.__sessionFeeRate
                : await this.getEffectiveFeeRate();
      const txSize = 250;
      const fees = Math.round(txSize * (feeRate * 1e8) / 1000);
      const total = Math.round(specificUtxo.amount * 1e8);
      const change = total - target - fees;

      if (change < 0) throw new Error('Fonds insuffisants');

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
          throw new Error('Données OP_RETURN trop volumineuses');
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
      console.error('[MESSAGING] Erreur création transaction OP_RETURN:', error);
      throw error;
    }
  }

  // === MAIN SEND MESSAGE FUNCTION ===
  async sendMessage(message, recipientBech32Address) {
    if (isOperationActive(OPERATION_TYPES.SEND_MESSAGE)) {
      throw new Error('Envoi de message déjà en cours');
    }
    
    startOperation(OPERATION_TYPES.SEND_MESSAGE);
    
    try {
      this.checkInitialized();

      const sessionFeeRate = await this.getEffectiveFeeRate();
      this.__sessionFeeRate = sessionFeeRate;
      
      const sendingMsg = getTranslation('messaging.message_sent_to', 'Envoi message vers: {{address}}', { address: recipientBech32Address });
      console.log('[MESSAGING]', sendingMsg);
      this.updateProgressIndicator(0, 1, 'Préparation');

      const encryptedMessage = await this.encryptMessage(message, recipientBech32Address);
      const chunks = this.splitIntoChunks(encryptedMessage, MESSAGING_CONFIG.CHUNK_SIZE);
      const messageId = JSON.parse(encryptedMessage).messageId;

      const dividedMsg = getTranslation('messaging.message_divided', 'Message divisé en {{chunks}} chunks', { chunks: chunks.length });
      console.log('[MESSAGING]', dividedMsg);

      let availableUtxos = await this.getFilteredAvailableUtxos(this.__sessionFeeRate);

      if (availableUtxos.length < chunks.length) {
        const missingCount = chunks.length - availableUtxos.length;
        const missingMsg = getTranslation('messaging.missing_optimized_utxos', 'Préparation de {{count}} UTXOs optimisés manquants...', { count: missingCount });
        console.log('[MESSAGING]', missingMsg);

        await this.prepareUtxosForMessage(missingCount, this.__sessionFeeRate);

        await this.sleep(3000);
        availableUtxos = await this.getFilteredAvailableUtxos(this.__sessionFeeRate);
      }

      if (availableUtxos.length < chunks.length) {
        const errorMsg = getTranslation('messaging.insufficient_utxos_no_conflict', 'UTXOs insuffisants pour envoyer {{chunks}} chunks sans conflit.', { chunks: chunks.length });
        throw new Error(errorMsg);
      }

      return await this.executeMessageSending(chunks, availableUtxos, messageId, recipientBech32Address);

    } catch (error) {
      console.error("[MESSAGING] Erreur envoi message:", error);
      throw error;
    } finally {
      endOperation(OPERATION_TYPES.SEND_MESSAGE);
    }
  }

  // === MESSAGE SCANNING ===
  async scanInboxMessages() {
    if (isOperationActive(OPERATION_TYPES.SCAN_MESSAGES)) {
      console.log('[MESSAGING] Scan déjà en cours, attente...');
      // Attendre que l'opération en cours se termine
      while (isOperationActive(OPERATION_TYPES.SCAN_MESSAGES)) {
        await this.sleep(500);
      }
      return this.messageCache.get('lastScanResult') || [];
    }
    
    startOperation(OPERATION_TYPES.SCAN_MESSAGES);
    
    try {
      this.checkInitialized();

      console.log('[MESSAGING] Scan des messages pour:', messagingState.bech32Address);

      const transactions = await this.getAddressTransactions(messagingState.bech32Address);
      const messages = new Map();

      for (const tx of transactions) {
        const opReturnData = tx.opReturnData;

        if (opReturnData && opReturnData.startsWith(MESSAGING_CONFIG.MESSAGE_PREFIX)) {
          const messageData = opReturnData.substring(MESSAGING_CONFIG.MESSAGE_PREFIX.length);
          const parts = messageData.split('_');

          if (parts.length < 4) {
            console.warn("[MESSAGING] Format de chunk invalide:", messageData);
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
            console.log(`[MESSAGING] Chunk ${chunkIdx}/${message.totalChunks} reçu pour message ${messageId}`);
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
                throw new Error(`Chunk manquant à l'index ${i}`);
              }
              sortedChunks.push(messageData.chunks.get(i));
            }
            const encryptedMessage = sortedChunks.join('');
            
            const reconstitutedMsg = getTranslation('messaging.message_reconstituted', 'Message {{id}} reconstitué, taille: {{size}}', 
              { id: messageId, size: encryptedMessage.length });
            console.log('[MESSAGING]', reconstitutedMsg);

            try {
              const __env = JSON.parse(encryptedMessage);
              if (__env && __env.recipient && __env.recipient !== messagingState.bech32Address) {
                const ignoredMsg = getTranslation('messaging.message_ignored_recipient', 'Message {{id}} ignoré (destiné à {{recipient}})', 
                  { id: messageId, recipient: __env.recipient });
                console.log('[MESSAGING]', ignoredMsg);
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
            if (error && error.message && /destiné/.test(error.message)) {
              const ignoredMsg2 = getTranslation('messaging.message_ignored_recipient', 'Message {{id}} ignoré (non destiné à {{address}}).', 
                { id: messageId, address: messagingState.bech32Address });
              console.log('[MESSAGING]', ignoredMsg2);
              continue;
            }
            
            const decryptErrorMsg = getTranslation('messaging.decryption_error', 'Erreur déchiffrement message {{id}}: {{error}}', 
              { id: messageId, error: error.message });
            console.error('[MESSAGING]', decryptErrorMsg);

            let errorType = "Erreur de déchiffrement";
            if (error.message.includes("GCM")) {
              errorType = "Données corrompues";
            } else if (error.message.includes("JSON")) {
              errorType = "Format invalide";
            } else if (error.message.includes("destiné")) {
              errorType = "Message non destiné";
            } else if (error.message.includes("ECDH")) {
              errorType = "Erreur cryptographique";
            }

            completeMessages.push({
              id: messageId,
              content: `[Message illisible - ${errorType}: ${error.message}]`,
              sender: messageData.senderAddress,
              timestamp: messageData.timestamp,
              status: 'error',
              verified: false,
              senderAddress: messageData.senderAddress,
              errorDetails: error.message
            });
          }
        } else {
          const incompleteMsg = getTranslation('messaging.message_incomplete', 'Message {{id}} incomplet: {{chunks}}/{{total}} chunks', 
            { id: messageId, chunks: messageData.chunks.size, total: messageData.totalChunks });
          console.log('[MESSAGING]', incompleteMsg);
        }
      }

      const sortedMessages = completeMessages.sort((a, b) => b.timestamp - a.timestamp);
      
      // Cache le résultat
      this.messageCache.set('lastScanResult', sortedMessages);
      
      return sortedMessages;
    } catch (error) {
      console.error('[MESSAGING] Erreur scan messages:', error);
      throw error;
    } finally {
      endOperation(OPERATION_TYPES.SCAN_MESSAGES);
    }
  }

  // === BLOCKCHAIN SCANNING ===
  async getAddressTransactions(address) {
    try {
      const searchingMsg = getTranslation('messaging.searching_pubkey_for', 'Recherche transactions pour: {{address}}', { address });
      console.log('[MESSAGING]', searchingMsg);
      const scan = await handleError500WithRetry(async () => {
        return await window.rpc("scantxoutset", ["start", [`addr(${address})`]]);
      });

      if (scan.unspents) {
        scan.unspents = scan.unspents.filter(u => u.amount <= MESSAGING_CONFIG.PROTECTION_LIMIT);
        const protectedMsg = getTranslation('messaging.utxos_protected', 'UTXOs protégés: {{count}}', { count: scan.unspents.length });
        console.log('[MESSAGING]', protectedMsg);
      }

      const transactions = [];
      const uniqueTxids = [...new Set(scan.unspents?.map(utxo => utxo.txid) || [])];
      const analyzeCompleteMsg = getTranslation('messaging.analyzing_transactions', 'Analyse complète de {{count}} transactions par lots...', { count: uniqueTxids.length });
      console.log('[MESSAGING]', analyzeCompleteMsg);

      let processed = 0;
      let totalAll = uniqueTxids.length;
      const BATCH_SIZE = 200;

      for (let i = 0; i < uniqueTxids.length; i += BATCH_SIZE) {
        const batch = uniqueTxids.slice(i, i + BATCH_SIZE);
        const batchNumber = Math.floor(i / BATCH_SIZE) + 1;
        const totalBatches = Math.ceil(uniqueTxids.length / BATCH_SIZE);

        const batchMsg = getTranslation('messaging.batch_sending', 'Lot {{current}}/{{total}}: {{count}} transactions', 
          { current: batchNumber, total: totalBatches, count: batch.length });
        console.log('[MESSAGING]', batchMsg);

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
            console.log(`[MESSAGING] Reprise des manquants: ${missing} restants (tentative ${attempt}/${MAX_RETRY})`);
            const delayMs = Math.min(4000, 200 * Math.pow(1.5, attempt)) + Math.floor(Math.random() * 250);
            await this.sleep(delayMs);
          }
        }

        if (remaining.size > 0) {
          console.warn(`[MESSAGING] Lot ${batchNumber}: ${remaining.size} tx introuvables après ${MAX_RETRY} tentatives.`);
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
        this.showScanProgress(processed, totalAll);

        const batchCompletedMsg = getTranslation('messaging.batch_completed_results', 'Lot {{batch}} terminé: {{valid}}/{{processed}} transactions analysées', 
          { batch: batchNumber, valid: validResults.length, processed: batch.length });
        console.log('[MESSAGING]', batchCompletedMsg);
        if (i + BATCH_SIZE < uniqueTxids.length) {
          await this.sleep(100);
        }
      }

      const totalAnalyzedMsg = getTranslation('messaging.total_analyzed', 'Total: {{count}} transactions complètement analysées', { count: transactions.length });
      console.log('[MESSAGING]', totalAnalyzedMsg);
      return transactions;

    } catch (error) {
      const errorMsg = getTranslation('messaging.error_retrieving_transactions', 'Erreur récupération transactions: {{error}}', { error: error.message });
      console.error('[MESSAGING]', errorMsg);
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
      console.error("[MESSAGING] Erreur décodage OP_RETURN:", error);
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

  // === PROGRESS INDICATORS ===
  updateProgressIndicator(current, total, action = 'Envoi') {
    const progressElement = document.getElementById('messageProgress');
    if (progressElement) {
      const percentage = Math.round((current / total) * 100);
      progressElement.innerHTML = `
        <div style="margin: 10px 0; padding: 15px; background: #f0f0f0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
          <div style="margin-bottom: 8px; font-weight: bold; color: #333;">${action}: ${current}/${total} chunks (${percentage}%)</div>
          <div style="width: 100%; background: #ddd; border-radius: 10px; height: 20px; overflow: hidden;">
            <div style="width: ${percentage}%; background: linear-gradient(90deg, #4b5e40, #6b7e60); height: 20px; border-radius: 10px; transition: width 0.3s ease;"></div>
          </div>
        </div>
      `;
    }
  }

  showScanProgress(current, total) {
    const progressElement = document.getElementById('messageProgress');
    if (progressElement) {
      const percentage = Math.round((current / total) * 100);
      progressElement.innerHTML = `
        <div style="text-align: center;">
          <div style="margin-bottom: 10px; font-weight: bold;">Analyse des messages</div>
          <div style="margin-bottom: 5px;">${current}/${total} transactions (${percentage}%)</div>
          <div style="width: 300px; background: #ddd; border-radius: 10px; height: 20px;">
            <div style="width: ${percentage}%; background: #4b5e40; height: 20px; border-radius: 10px; transition: width 0.3s;"></div>
          </div>
        </div>
      `;
    }
  }

  // === MISSING METHODS IMPLEMENTATION ===
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
    const filteredMsg = getTranslation('messaging.filtered_available_utxos', 'UTXOs disponibles filtrés: {{count}}', { count: filtered.length });
    console.log('[MESSAGING]', filteredMsg);

    return filtered;
  }

  async prepareUtxosForMessage(chunksNeeded, feeRateOverride) {
    // Implémentation simplifiée pour éviter les erreurs
    console.log(`[MESSAGING] Préparation de ${chunksNeeded} UTXOs nécessaire - fonctionnalité non encore implémentée`);
    return null;
  }

  async executeMessageSending(chunks, availableUtxos, messageId, recipientBech32Address) {
    const utxosToUse = availableUtxos.slice().sort((a,b) => a.amount - b.amount).slice(0, chunks.length);

    utxosToUse.forEach(utxo => this.markUtxoAsUsed(utxo.txid, utxo.vout));

    try {
      const parallelMsg = getTranslation('messaging.parallel_sending', 'Envoi en parallèle avec {{utxos}} UTXOs pour {{chunks}} chunks', 
        { utxos: utxosToUse.length, chunks: chunks.length });
      console.log('[MESSAGING]', parallelMsg);

      const preparedTransactions = [];
      
      for (let i = 0; i < chunks.length; i++) {
        const opReturnData = `${MESSAGING_CONFIG.MESSAGE_PREFIX}${messageId}_${i}_${chunks.length}_${chunks[i]}`;
        const selectedUtxo = utxosToUse[i];

        const preparingMsg = getTranslation('messaging.preparing_chunk', 'Préparation chunk {{current}}/{{total}} avec UTXO {{txid}}:{{vout}} ({{amount}} NITO)', 
          { current: i + 1, total: chunks.length, txid: selectedUtxo.txid, vout: selectedUtxo.vout, amount: selectedUtxo.amount });
        console.log('[MESSAGING]', preparingMsg);

        const hex = await this.createOpReturnTransaction(
          recipientBech32Address,
          MESSAGING_CONFIG.MESSAGE_FEE,
          opReturnData,
          selectedUtxo
        );
        preparedTransactions.push({ chunkIndex: i, hex, utxo: selectedUtxo });
      }

      const allPreparedMsg = getTranslation('messaging.all_transactions_prepared', 'Toutes les transactions préparées');
      console.log('[MESSAGING]', allPreparedMsg);

      const results = [];
      for (const transaction of preparedTransactions) {
        try {
          const txid = await handleError500WithRetry(async () => {
            return await window.rpc("sendrawtransaction", [transaction.hex]);
          });
          
          const sentMsg = getTranslation('messaging.chunk_sent', 'Chunk {{current}}/{{total}} envoyé: {{txid}}', 
            { current: transaction.chunkIndex + 1, total: chunks.length, txid });
          console.log('[MESSAGING]', sentMsg);
          
          results.push({
            success: true,
            txid: txid,
            chunkIndex: transaction.chunkIndex,
            transaction: transaction
          });
        } catch (error) {
          console.error(`[MESSAGING] Erreur envoi chunk ${transaction.chunkIndex}:`, error);
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

      const completedMsg = getTranslation('messaging.sending_completed', 'Envoi terminé: {{successful}}/{{total}} chunks réussis', 
        { successful: successfulResults.length, total: chunks.length });
      console.log('[MESSAGING]', completedMsg);

      const progressElement = document.getElementById('messageProgress');
      if (progressElement) {
        setTimeout(() => {
          progressElement.innerHTML = '';
        }, 3000);
      }

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
}

// === GLOBAL MESSAGING INSTANCE ===
const messaging = new NitoMessaging();

// === ENHANCED INITIALIZATION SYSTEM ===
let initializationAttempts = 0;
const MAX_INITIALIZATION_ATTEMPTS = 5;

async function initializeMessagingWhenReady() {
  // PROTECTION RENFORCÉE CONTRE LES DUPLICATIONS
  if (messagingInitialized || initializationInProgress) {
    console.log('[MESSAGING] Messagerie déjà initialisée ou en cours d\'initialisation');
    return;
  }

  if (initializationAttempts >= MAX_INITIALIZATION_ATTEMPTS) {
    console.log('[MESSAGING] Max messaging initialization attempts reached');
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
        console.log('[MESSAGING] Interface de messagerie activée avec Noble ECDH - Version 2.0.0');
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

// Event listener avec protection contre les duplications
let walletImportListenerAdded = false;

if (!walletImportListenerAdded) {
  eventBus.on(EVENTS.WALLET_IMPORTED, () => {
    setTimeout(() => {
      initializeMessagingWhenReady();
    }, 1000);
  });
  walletImportListenerAdded = true;
}

// === ENHANCED UI SETUP AVEC PROTECTION CONTRE LES DUPLICATIONS ===
function setupMessagingInterface() {
  // PROTECTION STRICTE CONTRE LA DUPLICATION D'INTERFACE
  if (messagingState.interfaceSetup) {
    console.log('[MESSAGING] Interface messagerie déjà configurée');
    return;
  }

  messagingState.interfaceSetup = true;

  // Nettoyer TOUS les anciens listeners en clonant les éléments
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

  // SETUP DES BOUTONS AVEC PROTECTION CONTRE LES DOUBLONS
  setupMessagingButtons();

  console.log('[MESSAGING] Interface de messagerie configurée - Version 2.0.0');
}

function setupMessagingButtons() {
  if (buttonListenersSetup) {
    console.log('[MESSAGING] Button listeners already setup');
    return;
  }
  
  buttonListenersSetup = true;

  // Publication de clé publique
  const publishButton = document.getElementById('publishPubkeyButton');
  if (publishButton) {
    publishButton.addEventListener('click', async () => {
      if (isOperationActive(OPERATION_TYPES.PUBLISH_PUBKEY)) {
        alert('Publication déjà en cours...');
        return;
      }
      
      try {
        showLoadingSpinner(true);
        const result = await messaging.publishPublicKey();
        console.log('[MESSAGING] Clé publique publiée avec succès !');
      } catch (error) {
        alert(`Erreur: ${error.message}`);
      } finally {
        showLoadingSpinner(false);
      }
    });
  }

  // Envoi de message
  const sendButton = document.getElementById('sendMessageButton');
  if (sendButton) {
    sendButton.addEventListener('click', () => {
      const message = document.getElementById('messageInput')?.value.trim();
      if (!message) {
        alert('Entrez un message');
        return;
      }
      if (message.length > MESSAGING_CONFIG.MAX_MESSAGE_LENGTH) {
        alert(`Message trop long: ${message.length}/${MESSAGING_CONFIG.MAX_MESSAGE_LENGTH} caractères`);
        return;
      }

      document.getElementById('sendMessageForm').style.display = 'block';
    });
  }

  // Confirmation d'envoi
  const confirmButton = document.getElementById('confirmSendButton');
  if (confirmButton) {
    confirmButton.addEventListener('click', async () => {
      if (isOperationActive(OPERATION_TYPES.SEND_MESSAGE)) {
        alert('Envoi déjà en cours...');
        return;
      }
      
      try {
        showLoadingSpinner(true);
        const message = document.getElementById('messageInput').value.trim();
        const recipient = document.getElementById('recipientAddress').value.trim();

        if (!message || !recipient) {
          alert('Remplissez tous les champs');
          return;
        }
        if (!recipient.startsWith('nito1')) {
          alert('Adresse bech32 invalide');
          return;
        }

        const result = await messaging.sendMessage(message, recipient);

        if (result.efficient) {
          console.log(`[MESSAGING] Message envoyé avec succès ! ID: ${result.messageId}, Transactions: ${result.chunks}/${result.totalChunks}, Coût: ${result.totalCost.toFixed(8)} NITO`);
        } else {
          alert(`Message envoyé partiellement: ${result.messageId}, ${result.chunks}/${result.totalChunks} chunks, coût: ${result.totalCost.toFixed(8)} NITO`);
        }

        document.getElementById('messageInput').value = '';
        document.getElementById('recipientAddress').value = '';
        document.getElementById('sendMessageForm').style.display = 'none';
        updateCharCounter();
      } catch (error) {
        alert(`Erreur: ${error.message}`);
      } finally {
        showLoadingSpinner(false);
      }
    });
  }

  // Annulation d'envoi
  const cancelButton = document.getElementById('cancelSendButton');
  if (cancelButton) {
    cancelButton.addEventListener('click', () => {
      document.getElementById('sendMessageForm').style.display = 'none';
    });
  }

  // Effacement du message
  const clearButton = document.getElementById('clearMessageButton');
  if (clearButton) {
    clearButton.addEventListener('click', () => {
      document.getElementById('messageInput').value = '';
      document.getElementById('sendMessageForm').style.display = 'none';
      updateCharCounter();
    });
  }

  // Actualisation des messages - CRITIQUE POUR LA STABILITÉ
  const refreshButton = document.getElementById('refreshMessagesButton');
  if (refreshButton) {
    refreshButton.addEventListener('click', async () => {
      if (isOperationActive(OPERATION_TYPES.REFRESH_MESSAGES)) {
        console.log('[MESSAGING] Refresh déjà en cours...');
        return;
      }
      
      startOperation(OPERATION_TYPES.REFRESH_MESSAGES);
      
      try {
        const originalText = refreshButton.textContent;
        const originalDisabled = refreshButton.disabled;
        
        refreshButton.disabled = true;
        refreshButton.textContent = getTranslation('loading.refreshing', '⌛ Actualisation...');
        
        showLoadingSpinner(true);
        const messages = await messaging.scanInboxMessages();
        displayMessages(messages);
        updateUnreadCounter(messages.filter(m => m.status === 'unread').length);
        
        // Restaurer l'état du bouton
        refreshButton.disabled = originalDisabled;
        refreshButton.textContent = originalText;
        
      } catch (error) {
        alert(`Erreur: ${error.message}`);
        // Restaurer même en cas d'erreur
        refreshButton.disabled = false;
        refreshButton.textContent = getTranslation('encrypted_messaging.refresh_messages', '🔄 Actualiser les messages');
      } finally {
        showLoadingSpinner(false);
        endOperation(OPERATION_TYPES.REFRESH_MESSAGES);
      }
    });
  }

  // Compteur de caractères
  const messageInput = document.getElementById('messageInput');
  if (messageInput) {
    messageInput.addEventListener('input', updateCharCounter);
  }
  
  updateCharCounter();

  console.log('[MESSAGING] Boutons de messagerie configurés avec protection anti-doublon');
}

// === UI UTILITY FUNCTIONS ===
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
    list.innerHTML = `<div class="message-item">Aucun message reçu</div>`;
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
    list.innerHTML = '<div class="message-item">Aucun message reçu</div>';
    list.style.display = 'block';
    return;
  }

  const messagesHtml = inboxItems.map(item => {
    const timestamp = item.time ? new Date(item.time * 1000).toLocaleString() : 'Date inconnue';
    const senderDisplay = item.senderBech32 || 'Expéditeur inconnu';

    return `
      <div class="inbox-row" onclick="showMessageModal('${item.id}', '${senderDisplay}', \`${item.body?.replace(/`/g, '\\`') || ''}\`)">
        <div>
          <div class="inbox-title">${senderDisplay}</div>
        </div>
        <div class="inbox-time">${timestamp}</div>
      </div>
    `;
  }).join('');

  list.innerHTML = messagesHtml;
  list.style.display = 'block';
}

function showMessageModal(messageId, senderAddress, messageBody) {
  const modal = document.getElementById('msgModal');
  const msgFrom = document.getElementById('msgFrom');
  const msgBody = document.getElementById('msgBody');

  if (modal && msgFrom && msgBody) {
    msgFrom.textContent = senderAddress;
    msgBody.textContent = messageBody;
    modal.style.display = 'block';

    // Event listeners pour fermer le modal
    const closeButtons = modal.querySelectorAll('[data-close]');
    closeButtons.forEach(btn => {
      btn.onclick = () => {
        modal.style.display = 'none';
      };
    });
  }
}

function updateUnreadCounter(count) {
  const unreadDiv = document.getElementById('unreadMessages');
  const countSpan = document.getElementById('unreadCount');
  if (unreadDiv && countSpan) {
    countSpan.textContent = count;
    unreadDiv.style.display = count > 0 ? 'block' : 'none';
  }
}

function showLoadingSpinner(show) {
  const spinner = document.getElementById('loadingSpinner');
  if (spinner) {
    spinner.style.display = show ? 'block' : 'none';
  }

  let progressElement = document.getElementById('messageProgress');
  if (show && !progressElement) {
    progressElement = document.createElement('div');
    progressElement.id = 'messageProgress';
    progressElement.style.position = 'fixed';
    progressElement.style.top = '50%';
    progressElement.style.left = '50%';
    progressElement.style.transform = 'translate(-50%, -50%)';
    progressElement.style.zIndex = '1000';
    progressElement.style.background = 'rgba(255, 255, 255, 0.95)';
    progressElement.style.padding = '20px';
    progressElement.style.borderRadius = '8px';
    progressElement.style.boxShadow = '0 4px 20px rgba(0,0,0,0.3)';
    document.body.appendChild(progressElement);
  } else if (!show && progressElement) {
    document.body.removeChild(progressElement);
  }
}

// === TESTING FUNCTIONS ===
window.testFullMessaging = async function() {
  try {
    const testSystemMsg = getTranslation('testing.full_messaging_test', 'Test complet du système de messagerie Noble ECDH');
    console.log('[MESSAGING]', testSystemMsg);

    const publishingMsg = getTranslation('testing.publishing_pubkey', '1. Publication de la clé publique...');
    console.log('[MESSAGING]', publishingMsg);
    await messaging.publishPublicKey();

    await new Promise(resolve => setTimeout(resolve, 3000));

    const sendingTestMsg = getTranslation('testing.sending_test_message', '2. Test d\'envoi de message à soi-même...');
    console.log('[MESSAGING]', sendingTestMsg);
    
    const testContentMsg = getTranslation('testing.test_message_content', 'Message de test crypté Noble ECDH');
    const testMessage = testContentMsg + " " + Date.now();
    const result = await messaging.sendMessage(testMessage, messagingState.bech32Address);

    const successMsg = getTranslation('testing.test_successful', 'Envoi réussi: {{result}}', { result });
    console.log('[MESSAGING]', successMsg, result);

    await new Promise(resolve => setTimeout(resolve, 10000));

    const scanningMsg = getTranslation('testing.scanning_received_messages', '3. Scan des messages reçus...');
    console.log('[MESSAGING]', scanningMsg);
    const messages = await messaging.scanInboxMessages();

    const foundMsg = getTranslation('testing.messages_found', 'Messages trouvés: {{count}}', { count: messages.length });
    console.log('[MESSAGING]', foundMsg);
    messages.forEach(msg => {
      console.log(`[MESSAGING] ${msg.id}: ${msg.content} (${msg.status})`);
    });

  } catch (error) {
    const failedMsg = getTranslation('testing.test_failed', 'Test échoué: {{error}}', { error });
    console.error('[MESSAGING]', failedMsg, error);
  }
};

// === GLOBAL COMPATIBILITY ===
export { messaging };
if (typeof window !== 'undefined') {
  window.messaging = messaging;
  window.renderInboxEmailStyle = renderInboxEmailStyle;
  window.showMessageModal = showMessageModal;
  window.isMessagingOperationActive = isOperationActive;
  window.startMessagingOperation = startOperation;
  window.endMessagingOperation = endOperation;
}

// === INITIALIZATION UNIQUE ===
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

console.log('Module de messagerie cryptée NITO avec Noble ECDH + AES-GCM chargé - Version 2.0.0');
