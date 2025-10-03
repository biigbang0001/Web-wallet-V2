import { MESSAGING_CONFIG, ELEMENT_IDS, UTXO_VALUES, getTranslation, sleep, sleepJitter } from './config.js';
import { eventBus, EVENTS } from './events.js';
import { armInactivityTimerSafely } from './security.js';
import { getBitcoinLibraries } from './vendor.js';
import { getWalletInfo } from './wallet.js';
import { 
  getTxDetailCached, 
  extractOpReturnData, 
  getTransactionSenderAddress,
  waitForConfirmation,
  handleError500WithRetry
} from './blockchain.js';
import { 
  FeeManager,
  filterUtxosByMinValue,
  createUniformUtxos,
  broadcastWithRetry
} from './transactions.js';
import {
  setupMessagingInterface,
  displayMessages,
  updateUnreadCounter,
  updateCharCounter
} from './ui-handlers.js';
import {
  createMessageProgressIndicator,
  updateMessageProgress,
  closeMessageProgress,
  showScanProgress,
  showSuccessPopup
} from './ui-popups.js';

// === NITO MESSAGING CLASS ===
export class NitoMessaging {
  constructor() {
    this.initialized = false;
    this.myBech32Address = null;
    this.myPublicKey = null;
    this.messageCache = new Map();
    this.formIsOpen = false;
  }

  async initialize() {
    if (this.initialized) return true;

    try {
      const walletInfo = await getWalletInfo();
      
      if (!walletInfo || !walletInfo.isReady) {
        console.warn(`[MESSAGING] ${getTranslation('messaging.wallet_not_initialized', 'Wallet not initialized')}`);
        return false;
      }

      this.myBech32Address = walletInfo.addresses.bech32;

      if (!this.myBech32Address || !this.myBech32Address.startsWith('nito1')) {
        console.warn(`[MESSAGING] ${getTranslation('messaging.invalid_bech32_address', 'Invalid bech32 address')}`);
        return false;
      }

      if (window.getWalletPublicKey) {
        const pubKeyBuffer = await window.getWalletPublicKey();
        if (pubKeyBuffer) {
          this.myPublicKey = Buffer.from(pubKeyBuffer).toString('hex');
        }
      }

      this.initialized = true;
      console.log(`[MESSAGING] ${getTranslation('loading.wallet_setup', 'Setting up wallet...')} successful`);
      return true;
    } catch (error) {
      console.error(`[MESSAGING] ${getTranslation('errors.initialization_failed', 'App initialization failed. Please refresh the page.')}`, error);
      return false;
    }
  }

  clearCaches() {
    this.messageCache.clear();
    console.log(`[MESSAGING] ${getTranslation('loading.cache_clearing', 'Clearing caches...')} complete`);
  }

  // === ECDH KEY DERIVATION ===
  async deriveSharedKey(theirPublicKeyHex) {
    let keyPair = null;
    try {
      if (!window.ecc || !window.getWalletKeyPair) {
        throw new Error(getTranslation('messaging.missing_keys_ecdh', 'Missing keys for ECDH'));
      }

      const theirPubKey = Buffer.from(theirPublicKeyHex, 'hex');
      keyPair = await window.getWalletKeyPair();
      
      if (!keyPair || !keyPair.privateKey) {
        throw new Error(getTranslation('messaging.invalid_private_key_ecdh', 'Invalid private key for ECDH'));
      }

      const sharedSecret = window.ecc.pointMultiply(
        Uint8Array.from(theirPubKey),
        Uint8Array.from(keyPair.privateKey),
        true
      );

      if (!sharedSecret || sharedSecret.length < 33) {
        throw new Error(getTranslation('messaging.shared_key_derivation_error', 'Shared key derivation error'));
      }

      const sharedKey = Buffer.from(sharedSecret.slice(1, 33));
      
      // Security: Clean up private key immediately after use
      if (keyPair.privateKey) {
        if (Buffer.isBuffer(keyPair.privateKey)) {
          keyPair.privateKey.fill(0);
        } else if (keyPair.privateKey instanceof Uint8Array) {
          keyPair.privateKey.fill(0);
        }
      }
      
      return sharedKey;
    } catch (error) {
      // Security: Clean up on error
      if (keyPair?.privateKey) {
        try {
          if (Buffer.isBuffer(keyPair.privateKey)) {
            keyPair.privateKey.fill(0);
          } else if (keyPair.privateKey instanceof Uint8Array) {
            keyPair.privateKey.fill(0);
          }
        } catch (e) {}
      }
      console.error(`[MESSAGING] ${getTranslation('messaging.ecdh_derivation_error', 'Shared key derivation error: {{error}}', { error: error.message })}`);
      throw error;
    }
  }

  // === AES-GCM ENCRYPTION ===
  async encryptWithAES(plaintext, sharedKey) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(plaintext);
      const iv = crypto.getRandomValues(new Uint8Array(12));

      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        sharedKey,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );

      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        cryptoKey,
        data
      );

      const combined = new Uint8Array(iv.length + encrypted.byteLength);
      combined.set(iv, 0);
      combined.set(new Uint8Array(encrypted), iv.length);

      return Buffer.from(combined).toString('hex');
    } catch (error) {
      console.error(`[MESSAGING] ${getTranslation('messaging.encryption_error', 'Encryption error: {{error}}', { error: error.message })}`);
      throw new Error(getTranslation('messaging.encryption_error', 'Encryption error: {{error}}', { error: error.message }));
    }
  }

  // === AES-GCM DECRYPTION ===
  async decryptWithAES(ciphertextHex, sharedKey) {
    try {
      const combined = Buffer.from(ciphertextHex, 'hex');
      
      if (combined.length < 28) {
        throw new Error(getTranslation('messaging.invalid_encrypted_data', 'Invalid encrypted data'));
      }
      
      const iv = combined.slice(0, 12);
      const ciphertext = combined.slice(12);

      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        sharedKey,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        cryptoKey,
        ciphertext
      );

      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (error) {
      console.error(`[MESSAGING] ${getTranslation('messaging.decryption_error_detail', 'Decryption error: {{error}}', { error: error.message })}`);
      throw new Error(getTranslation('messaging.decryption_error_detail', 'Decryption error: {{error}}', { error: error.message }));
    }
  }

  // === PUBLIC KEY PUBLICATION ===
  async publishPublicKey() {
    armInactivityTimerSafely();
    
    let keyPair = null;
    let publicKey = null;

    try {
      if (!this.initialized) {
        const success = await this.initialize();
        if (!success) {
          throw new Error(getTranslation('transactions.import_wallet_first', 'Import a wallet first.'));
        }
      }

      if (!this.myPublicKey) {
        throw new Error(getTranslation('security.invalid_private_key', 'Invalid private key'));
      }

      const walletInfo = await getWalletInfo();
      if (!walletInfo.isReady) {
        throw new Error(getTranslation('messaging.wallet_not_initialized', 'Wallet not initialized'));
      }

      const myAddress = walletInfo.addresses.bech32;
      const pubKeyMessage = `${MESSAGING_CONFIG.PUBKEY_PREFIX}${this.myPublicKey}`;
      const hexMessage = Buffer.from(pubKeyMessage, 'utf8').toString('hex');

      if (hexMessage.length > 160) {
        throw new Error(getTranslation('messaging.opreturn_data_too_large', 'OP_RETURN data too large (max 75 bytes)'));
      }

      const scriptHex = `6a${(hexMessage.length / 2).toString(16).padStart(2, '0')}${hexMessage}`;
      const { bitcoin } = await getBitcoinLibraries();
      const psbt = new bitcoin.Psbt({ network: window.NITO_NETWORK });
      psbt.setVersion(2);

      const isHD = window.importType === 'hd';
      const hdWallet = isHD && window.hdManager ? window.hdManager.hdWallet : null;

      let utxos = await window.utxos(myAddress, isHD, hdWallet);
      utxos = filterUtxosByMinValue(utxos, UTXO_VALUES.MIN_TRANSACTION, 'p2wpkh');

      if (!utxos || utxos.length === 0) {
        throw new Error(getTranslation('transactions.no_utxos_available', 'No UTXOs available'));
      }

      const sourceUtxo = utxos[0];
      const inputValue = Math.round(sourceUtxo.amount * 1e8);
      const scriptBuffer = Buffer.from(sourceUtxo.scriptPubKey, 'hex');

      psbt.addInput({
        hash: sourceUtxo.txid,
        index: sourceUtxo.vout,
        witnessUtxo: { script: scriptBuffer, value: inputValue }
      });

      psbt.addOutput({
        script: Buffer.from(scriptHex, 'hex'),
        value: 0
      });

      psbt.addOutput({
        address: myAddress,
        value: UTXO_VALUES.MESSAGE_UTXO
      });

      const feeManager = new FeeManager();
      const feeRate = await feeManager.getRealFeeRate();
      
      let vbytes = feeManager.estimateVBytes('p2wpkh', 1, 2);
      let estimatedFee = feeManager.calculateFeeForVsize(vbytes, feeRate);
      let changeValue = inputValue - UTXO_VALUES.MESSAGE_UTXO - estimatedFee;

      if (changeValue > UTXO_VALUES.MIN_TRANSACTION) {
        vbytes = feeManager.estimateVBytes('p2wpkh', 1, 3);
        estimatedFee = feeManager.calculateFeeForVsize(vbytes, feeRate);
        changeValue = inputValue - UTXO_VALUES.MESSAGE_UTXO - estimatedFee;
        
        if (changeValue > UTXO_VALUES.MIN_TRANSACTION) {
          psbt.addOutput({
            address: myAddress,
            value: changeValue
          });
        }
      }

      console.log(`[MESSAGING] Publishing public key - Fee rate: ${feeRate}, vBytes: ${vbytes}, Fee: ${estimatedFee} sats, Change: ${changeValue} sats`);

      if (changeValue < 0) {
        throw new Error(getTranslation('messaging.insufficient_funds', 'Insufficient funds'));
      }

      keyPair = await window.getWalletKeyPair();
      publicKey = await window.getWalletPublicKey();
      
      if (!keyPair || !publicKey) {
        throw new Error(getTranslation('transactions.missing_keypair', 'Missing keypair for UTXO {{index}}', { index: 0 }));
      }

      const signer = {
        network: keyPair.network,
        privateKey: Buffer.from(keyPair.privateKey),
        publicKey: Buffer.from(publicKey),
        sign: (hash) => Buffer.from(keyPair.sign(hash))
      };

      psbt.signInput(0, signer);
      
      // Security: Clean up keys immediately after signing
      if (signer.privateKey) signer.privateKey.fill(0);
      if (keyPair.privateKey) keyPair.privateKey.fill(0);
      
      psbt.finalizeAllInputs();

      const tx = psbt.extractTransaction();
      const txHex = tx.toHex();
      const txid = await broadcastWithRetry(txHex);

      await showSuccessPopup(txid);
      console.log(`[MESSAGING] ${getTranslation('messaging.pubkey_published', 'Public key published, TXID: {{txid}}', { txid })}`);

    } catch (error) {
      console.error(`[MESSAGING] ${getTranslation('messaging.publication_error', 'Publication error: {{error}}', { error: error.message })}`);
      alert(getTranslation('messaging.publication_error', 'Publication error: {{error}}', { error: error.message }));
    } finally {
      // Security: Final cleanup
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

  // === PUBLIC KEY SEARCH ===
  async findPublicKey(address) {
    try {
      console.log(`[MESSAGING] ${getTranslation('messaging.searching_pubkey_for', 'Searching public key for:')} ${address.substring(0, 20)}...`);
      
      if (!window.rpc) {
        throw new Error(getTranslation('errors.rpc_unavailable', 'RPC function unavailable'));
      }

      const scan = await window.rpc("scantxoutset", ["start", [`addr(${address})`]]);
      
      if (!scan.success || !scan.unspents || !scan.unspents.length) {
        console.log(`[MESSAGING] ${getTranslation('messaging.no_pubkey_found_for', 'No public key found for:')} ${address.substring(0, 20)}...`);
        return null;
      }

      console.log(`[MESSAGING] Found ${scan.unspents.length} UTXOs, ${getTranslation('loading.blockchain_scan', 'scanning blockchain...')}`);

      const scannedTxids = new Set();

      for (const utxo of scan.unspents) {
        if (scannedTxids.has(utxo.txid)) continue;
        scannedTxids.add(utxo.txid);

        try {
          const txDetail = await window.rpc("getrawtransaction", [utxo.txid, true]);
          if (!txDetail || !txDetail.vout) continue;

          for (const output of txDetail.vout) {
            if (!output.scriptPubKey || !output.scriptPubKey.hex) continue;

            const opReturnData = extractOpReturnData(output.scriptPubKey.hex);
            if (!opReturnData) continue;

            const decoded = Buffer.from(opReturnData, 'hex').toString('utf8');
            if (decoded.startsWith(MESSAGING_CONFIG.PUBKEY_PREFIX)) {
              const pubKeyHex = decoded.substring(MESSAGING_CONFIG.PUBKEY_PREFIX.length);
              if (/^[0-9a-fA-F]{66}$/.test(pubKeyHex)) {
                console.log(`[MESSAGING] ${getTranslation('messaging.pubkey_found_validated_for', 'PUBLIC KEY FOUND AND VALIDATED for:')} ${address.substring(0, 20)}... in tx ${utxo.txid.substring(0, 8)}...`);
                return pubKeyHex;
              }
            }
          }
        } catch (err) {
          console.warn(`[MESSAGING] ${getTranslation('explorer.checking_explorer', 'Error while checking explorer:')} tx ${utxo.txid.substring(0, 8)}:`, err);
          continue;
        }
      }

      console.log(`[MESSAGING] Scanned ${scannedTxids.size} ${getTranslation('messaging.transactions', 'transactions')}, ${getTranslation('messaging.no_pubkey_found_for', 'no public key found for')} ${address.substring(0, 20)}...`);
      return null;
    } catch (error) {
      console.error(`[MESSAGING] ${getTranslation('explorer.checking_explorer', 'Error while checking explorer:')}`, error);
      return null;
    }
  }

  // === MESSAGE ENCRYPTION ===
  async encryptMessage(recipientAddress, plaintext) {
    try {
      console.log(`[MESSAGING] ${getTranslation('messaging.searching_pubkey_for', 'Searching public key for:')} ${recipientAddress.substring(0, 20)}...`);
      const recipientPubKey = await this.findPublicKey(recipientAddress);
      
      if (!recipientPubKey) {
        throw new Error(getTranslation('messaging.recipient_pubkey_not_found', 'Recipient public key not found. They must publish their public key first.'));
      }
      
      console.log(`[MESSAGING] ${getTranslation('messaging.encryption_ecdh_for', 'ECDH encryption for:')} ${recipientAddress.substring(0, 20)}...`);
      const sharedKey = await this.deriveSharedKey(recipientPubKey);
      
      console.log(`[MESSAGING] ${getTranslation('loading.calculating', 'Calculating...')}`);
      const encryptedHex = await this.encryptWithAES(plaintext, sharedKey);
      
      // Security: Clean up shared key
      if (sharedKey && Buffer.isBuffer(sharedKey)) {
        sharedKey.fill(0);
      }

      return encryptedHex;
    } catch (error) {
      console.error(`[MESSAGING] ${getTranslation('messaging.encryption_error', 'Encryption error: {{error}}', { error: error.message })}`);
      throw error;
    }
  }

  // === MESSAGE DECRYPTION ===
  async decryptMessage(senderAddress, ciphertextHex) {
    try {
      console.log(`[MESSAGING] ${getTranslation('messaging.decryption_ecdh_completed', 'ECDH decryption completed, message verified:')} ${senderAddress.substring(0, 20)}...`);
      const senderPubKey = await this.findPublicKey(senderAddress);
      
      if (!senderPubKey) {
        throw new Error(getTranslation('messaging.sender_pubkey_not_found', 'Cannot find sender\'s public key'));
      }

      const sharedKey = await this.deriveSharedKey(senderPubKey);
      const plaintext = await this.decryptWithAES(ciphertextHex, sharedKey);
      
      // Security: Clean up shared key
      if (sharedKey && Buffer.isBuffer(sharedKey)) {
        sharedKey.fill(0);
      }

      return plaintext;
    } catch (error) {
      console.error(`[MESSAGING] ${getTranslation('messaging.decryption_error_detail', 'Decryption error: {{error}}', { error: error.message })}`);
      throw error;
    }
  }

  // === SEND MESSAGE ===
  async sendMessage() {
    armInactivityTimerSafely();

    try {
      if (!this.initialized) {
        const success = await this.initialize();
        if (!success) {
          throw new Error(getTranslation('transactions.import_wallet_first', 'Import a wallet first.'));
        }
      }

      const messageInput = document.getElementById(ELEMENT_IDS.MESSAGE_INPUT);
      const sendMessageForm = document.getElementById('sendMessageForm');

      if (!messageInput) {
        alert(getTranslation('errors.fill_destination_amount', 'Please fill in the destination address and amount'));
        return;
      }

      if (!this.formIsOpen) {
        const messageText = messageInput.value.trim();

        if (!messageText) {
          alert(getTranslation('messaging.enter_message', 'Enter a message'));
          messageInput.focus();
          return;
        }

        if (messageText.length > MESSAGING_CONFIG.MAX_MESSAGE_LENGTH) {
          alert(getTranslation('messaging.message_too_long', 'Message too long: {{length}}/{{max}} characters', {
            length: messageText.length,
            max: MESSAGING_CONFIG.MAX_MESSAGE_LENGTH
          }));
          messageInput.focus();
          return;
        }

        if (sendMessageForm) {
          sendMessageForm.style.display = 'block';
          this.formIsOpen = true;
        }
        return;
      }

      const recipientInput = document.getElementById(ELEMENT_IDS.RECIPIENT_ADDRESS);

      if (!recipientInput) {
        alert(getTranslation('messaging.fill_all_fields', 'Fill in all fields'));
        return;
      }

      const messageText = messageInput.value.trim();
      const recipientAddress = recipientInput.value.trim();

      if (!recipientAddress) {
        alert(getTranslation('messaging.no_recipient_address', 'No recipient address provided'));
        recipientInput.focus();
        return;
      }

      if (!recipientAddress.startsWith('nito1') || recipientAddress.startsWith('nito1p')) {
        alert(getTranslation('messaging.invalid_bech32_address', 'Invalid bech32 address'));
        recipientInput.focus();
        return;
      }

      console.log(`[MESSAGING] ${getTranslation('messaging.encryption_ecdh_for', 'ECDH encryption for:')} ${recipientAddress}`);
      const encryptedMessage = await this.encryptMessage(recipientAddress, messageText);
      console.log(`[MESSAGING] ${getTranslation('messaging.encryption_successful', 'Message encrypted with ECDH + AES-GCM')}`);
      
      const walletInfo = await getWalletInfo();
      if (!walletInfo.isReady) {
        throw new Error(getTranslation('messaging.wallet_not_initialized', 'Wallet not initialized'));
      }

      const myAddress = walletInfo.addresses.bech32;
      const messageWithSender = `FROM:${myAddress}|${encryptedMessage}`;
      const messageWithPrefix = MESSAGING_CONFIG.MESSAGE_PREFIX + messageWithSender;
      const chunks = this.splitIntoChunks(messageWithPrefix, MESSAGING_CONFIG.CHUNK_SIZE);

      console.log(`[MESSAGING] ${getTranslation('messaging.message_divided', 'Message divided into {{chunks}} chunks', { chunks: chunks.length })}`);

      const isHD = window.importType === 'hd';
      const hdWallet = isHD && window.hdManager ? window.hdManager.hdWallet : null;

      let availableUtxos = await window.utxos(myAddress, isHD, hdWallet);
      availableUtxos = filterUtxosByMinValue(availableUtxos, UTXO_VALUES.MIN_TRANSACTION, 'p2wpkh');

      console.log(`[MESSAGING] Available UTXOs (>= ${UTXO_VALUES.MIN_TRANSACTION} sats): ${availableUtxos.length}`);

      if (availableUtxos.length === 0) {
        alert(getTranslation('transactions.no_suitable_utxos', 'No suitable mature UTXOs available') + `. ${getTranslation('consolidate.cta', 'Consolidate UTXOs')}`);
        return;
      }

      if (availableUtxos.length < chunks.length) {
        console.log(`[MESSAGING] ${getTranslation('progress_indicators.preparing_missing_utxos', 'Preparing {{count}} UTXOs...', { count: chunks.length })}`);
        
        createMessageProgressIndicator();
        updateMessageProgress(0, 1, getTranslation('progress_indicators.preparing_utxos_percentage', 'Preparing UTXOs: {{percentage}}%', { percentage: 0 }));

        const feeManager = new FeeManager();
        const feeRate = await feeManager.getRealFeeRate();
        const chunkValueSats = feeManager.calculateMessageChunkAmount(feeRate);

        const result = await createUniformUtxos(chunks.length, chunkValueSats, myAddress);
        
        updateMessageProgress(1, 1, getTranslation('progress_indicators.utxos_ready', 'UTXOs ready'));
        await sleep(500);
        
        availableUtxos = result.utxos;
        console.log(`[MESSAGING] Created ${availableUtxos.length} UTXOs via single split transaction: ${result.txid}`);
      }

      const selectedUtxos = availableUtxos.slice(0, chunks.length);

      if (selectedUtxos.length < chunks.length) {
        throw new Error(getTranslation('transactions.insufficient_funds_simple', 'Insufficient funds'));
      }

      createMessageProgressIndicator();
      const txids = await this.executeMessageSending(chunks, selectedUtxos, recipientAddress);
      closeMessageProgress(1000);

      const lastTxid = txids[txids.length - 1];
      console.log(`[MESSAGING] ${getTranslation('messaging.message_sent_success', 'Message sent successfully!')} ${txids.length} ${getTranslation('messaging.transactions', 'transactions')}`);

      await showSuccessPopup(lastTxid);
      
      messageInput.value = '';
      recipientInput.value = '';
      if (sendMessageForm) {
        sendMessageForm.style.display = 'none';
        this.formIsOpen = false;
      }
      updateCharCounter();

    } catch (error) {
      closeMessageProgress(0);
      console.error(`[MESSAGING] ${getTranslation('errors.broadcast_failed', 'Broadcast failed')}`, error);
      alert(getTranslation('errors.broadcast_failed', 'Broadcast failed') + `: ${error.message}`);
    }
  }

  // === MESSAGE SENDING EXECUTION ===
  async executeMessageSending(chunks, utxos, recipientAddress) {
    const { bitcoin } = await getBitcoinLibraries();
    const txids = [];
    const failedChunks = [];
    const feeManager = new FeeManager();
    const feeRate = await feeManager.getRealFeeRate();

    let keyPair = null;
    let publicKey = null;
    
    try {
      keyPair = await window.getWalletKeyPair();
      publicKey = await window.getWalletPublicKey();
      
      if (!keyPair || !publicKey) {
        throw new Error(getTranslation('transactions.missing_keypair', 'Missing keypair for UTXO {{index}}', { index: 0 }));
      }

      const signer = {
        network: keyPair.network,
        privateKey: Buffer.from(keyPair.privateKey),
        publicKey: Buffer.from(publicKey),
        sign: (hash) => {
          const signature = keyPair.sign(hash);
          return Buffer.from(signature);
        }
      };

      const BATCH_SIZE = 24;
      let splitTxid = null;
      let lastUtxoVout = null;
      let waitedForConfirmation = false;

      for (let i = 0; i < chunks.length; i++) {
        if (i === BATCH_SIZE && splitTxid && lastUtxoVout !== null && !waitedForConfirmation) {
          updateMessageProgress(i + 1, chunks.length, getTranslation('messaging.waiting_split_confirmation', 'Waiting for split confirmation...'));
          
          console.log(`[MESSAGING] Batch complete, ${getTranslation('confirmations.checking_confirmation', 'Checking confirmations...')}`);
          
          const confirmed = await this.waitForSplitConfirmation(splitTxid, lastUtxoVout, 300000);
          
          if (!confirmed) {
            failedChunks.push(i);
            throw new Error(getTranslation('messaging.confirmation_timeout', 'Confirmation timeout'));
          }
          
          waitedForConfirmation = true;
          console.log(`[MESSAGING] ${getTranslation('confirmations.confirmed', 'Confirmed')}`);
          await sleep(2000);
        }

        updateMessageProgress(i + 1, chunks.length, getTranslation('progress_indicators.broadcasting_chunks', 'Broadcasting {{current}}/{{total}}', {
          current: i + 1,
          total: chunks.length
        }));

        const chunk = chunks[i];
        const utxo = utxos[i];

        if (i === 0 && utxo.txid) {
          splitTxid = utxo.txid;
          lastUtxoVout = chunks.length - 1;
          console.log(`[MESSAGING] Using split TX ${splitTxid.substring(0, 8)}...`);
        }

        const hexChunk = Buffer.from(chunk, 'utf8').toString('hex');
        const scriptHex = `6a${(hexChunk.length / 2).toString(16).padStart(2, '0')}${hexChunk}`;

        const psbt = new bitcoin.Psbt({ network: window.NITO_NETWORK });
        psbt.setVersion(2);

        const inputValue = Math.round(utxo.amount * 1e8);
        const scriptBuffer = Buffer.from(utxo.scriptPubKey, 'hex');

        psbt.addInput({
          hash: utxo.txid,
          index: utxo.vout,
          witnessUtxo: { script: scriptBuffer, value: inputValue }
        });

        psbt.addOutput({
          script: Buffer.from(scriptHex, 'hex'),
          value: 0
        });

        psbt.addOutput({
          address: recipientAddress,
          value: UTXO_VALUES.MESSAGE_UTXO
        });

        let vbytes = feeManager.estimateVBytes('p2wpkh', 1, 2);
        let estimatedFee = feeManager.calculateFeeForVsize(vbytes, feeRate);
        let changeValue = inputValue - UTXO_VALUES.MESSAGE_UTXO - estimatedFee;

        if (changeValue > UTXO_VALUES.MIN_TRANSACTION) {
          vbytes = feeManager.estimateVBytes('p2wpkh', 1, 3);
          estimatedFee = feeManager.calculateFeeForVsize(vbytes, feeRate);
          changeValue = inputValue - UTXO_VALUES.MESSAGE_UTXO - estimatedFee;
          
          if (changeValue > UTXO_VALUES.MIN_TRANSACTION) {
            psbt.addOutput({
              address: recipientAddress,
              value: changeValue
            });
          }
        }

        if (changeValue < 0) {
          failedChunks.push(i);
          throw new Error(getTranslation('messaging.insufficient_funds', 'Insufficient funds'));
        }

        psbt.signInput(0, signer);
        psbt.finalizeAllInputs();

        const tx = psbt.extractTransaction();
        const txHex = tx.toHex();

        try {
          const txid = await broadcastWithRetry(txHex);
          txids.push(txid);
          
          console.log(`[MESSAGING] ${getTranslation('messaging.chunk_sent', 'Chunk {{current}}/{{total}} sent: {{txid}}', {
            current: i + 1,
            total: chunks.length,
            txid: txid.substring(0, 8) + '...'
          })}`);
        } catch (error) {
          failedChunks.push(i);
          console.error(`[MESSAGING] ${getTranslation('messaging.chunk_abandoned', 'Chunk {{chunk}} abandoned after {{attempts}} attempts', {chunk: i + 1, attempts: 1})}`);
          break;
        }

        await sleepJitter(400, 600, true);
      }

      if (failedChunks.length > 0) {
        throw new Error(getTranslation('messaging.sending_completed', 'Sending completed: {{successful}}/{{total}} chunks succeeded', {
          successful: txids.length,
          total: chunks.length
        }));
      }

      return txids;

    } finally {
      // Security: Clean up keys after all operations
      if (keyPair?.privateKey) {
        try {
          if (Buffer.isBuffer(keyPair.privateKey)) {
            keyPair.privateKey.fill(0);
          } else if (keyPair.privateKey instanceof Uint8Array) {
            keyPair.privateKey.fill(0);
          }
        } catch (e) {}
      }
      if (signer?.privateKey) {
        try {
          if (Buffer.isBuffer(signer.privateKey)) {
            signer.privateKey.fill(0);
          }
        } catch (e) {}
      }
    }
  }

  // === WAIT FOR SPLIT CONFIRMATION ===
  async waitForSplitConfirmation(txid, vout, maxWaitTime = 300000) {
    const startTime = Date.now();
    console.log(`[MESSAGING] ${getTranslation('confirmations.checking_confirmation', 'Checking confirmations...')} split TX ${txid.substring(0, 8)}... (checking UTXO vout ${vout})`);

    while (Date.now() - startTime < maxWaitTime) {
      try {
        if (!window.rpc) {
          await sleep(10000);
          continue;
        }

        const utxoInfo = await window.rpc('gettxout', [txid, vout, true]);
        
        if (utxoInfo && utxoInfo.confirmations && utxoInfo.confirmations >= 1) {
          console.log(`[MESSAGING] Split TX ${txid.substring(0, 8)}... UTXO vout ${vout} ${getTranslation('confirmations.confirmed', 'confirmed')} (${utxoInfo.confirmations} confirmations)`);
          return true;
        }

        await sleep(10000);
      } catch (error) {
        console.warn(`[MESSAGING] ${getTranslation('explorer.checking_explorer', 'Error while checking explorer:')}`, error);
        await sleep(10000);
      }
    }

    console.warn(`[MESSAGING] Timeout for ${txid.substring(0, 8)}...`);
    return false;
  }

  // === SPLIT INTO CHUNKS ===
  splitIntoChunks(message, chunkSize) {
    const chunks = [];
    for (let i = 0; i < message.length; i += chunkSize) {
      chunks.push(message.substring(i, i + chunkSize));
    }
    return chunks;
  }

  // === SCAN INBOX MESSAGES ===
  async scanInboxMessages() {
    armInactivityTimerSafely();

    try {
      if (!this.initialized) {
        const success = await this.initialize();
        if (!success) {
          throw new Error(getTranslation('transactions.import_wallet_first', 'Import a wallet first.'));
        }
      }

      const walletInfo = await getWalletInfo();
      if (!walletInfo.isReady) {
        throw new Error(getTranslation('messaging.wallet_not_initialized', 'Wallet not initialized'));
      }

      const myAddress = walletInfo.addresses.bech32;
      const isHD = window.importType === 'hd';
      const hdWallet = isHD && window.hdManager ? window.hdManager.hdWallet : null;

      console.log(`[MESSAGING] ${getTranslation('messaging.analyzing_messages', 'Analyzing messages')}`);

      const utxos = await window.utxos(myAddress, isHD, hdWallet);
      if (!utxos || !utxos.length) {
        displayMessages([]);
        updateUnreadCounter(0);
        return;
      }

      const transactions = new Set();
      utxos.forEach(u => transactions.add(u.txid));

      const txArray = Array.from(transactions);
      const messages = new Map();

      createMessageProgressIndicator();

      for (let i = 0; i < txArray.length; i++) {
        showScanProgress(i + 1, txArray.length);

        const txid = txArray[i];
        
        try {
          const txDetail = await getTxDetailCached(txid);
          if (!txDetail || !txDetail.vout) continue;

          for (const output of txDetail.vout) {
            if (!output.scriptPubKey || !output.scriptPubKey.hex) continue;

            const opReturnData = extractOpReturnData(output.scriptPubKey.hex);
            if (!opReturnData) continue;

            const decoded = Buffer.from(opReturnData, 'hex').toString('utf8');
            
            if (decoded.startsWith(MESSAGING_CONFIG.MESSAGE_PREFIX)) {
              const chunk = decoded.substring(MESSAGING_CONFIG.MESSAGE_PREFIX.length);
              
              if (!messages.has(txid)) {
                messages.set(txid, {
                  sender: null,
                  chunks: [],
                  timestamp: txDetail.time ? txDetail.time * 1000 : Date.now()
                });
              }
              
              messages.get(txid).chunks.push(chunk);
            }
          }
        } catch (err) {
          console.warn(`[MESSAGING] ${getTranslation('explorer.checking_explorer', 'Error while checking explorer:')} tx ${txid}:`, err);
          continue;
        }

        await sleepJitter(10, 50, true);
      }

      closeMessageProgress(500);

      const decryptedMessages = [];

      for (const [txid, msgData] of messages.entries()) {
        try {
          const fullMessage = msgData.chunks.join('');
          
          const senderMatch = fullMessage.match(/^FROM:([a-z0-9]+)\|/);
          let senderAddress = getTranslation('messaging.unknown_sender', 'Unknown sender');
          let encryptedData = fullMessage;
          
          if (senderMatch) {
            senderAddress = senderMatch[1];
            encryptedData = fullMessage.substring(senderMatch[0].length);
            console.log(`[MESSAGING] ${getTranslation('messaging.message_sent_to', 'Message sent to:')} ${senderAddress.substring(0, 20)}...`);
          } else {
            console.warn(`[MESSAGING] No sender address found in message ${txid.substring(0, 8)}...`);
            continue;
          }
          
          const decrypted = await this.decryptMessage(senderAddress, encryptedData);
          
          decryptedMessages.push({
            id: txid,
            from: senderAddress,
            body: decrypted,
            timestamp: msgData.timestamp,
            read: false
          });
        } catch (err) {
          console.warn(`[MESSAGING] ${getTranslation('messaging.decryption_error', 'Decryption error')} ${txid.substring(0, 8)}...:`, err);
        }
      }

      decryptedMessages.sort((a, b) => b.timestamp - a.timestamp);

      displayMessages(decryptedMessages);
      updateUnreadCounter(decryptedMessages.length);

      console.log(`[MESSAGING] Found ${decryptedMessages.length} ${getTranslation('messaging.no_messages_received', 'messages')}`);

    } catch (error) {
      closeMessageProgress(0);
      console.error(`[MESSAGING] ${getTranslation('errors.import_error', 'Import error')}`, error);
      alert(getTranslation('errors.import_error', 'Import error') + `: ${error.message}`);
    }
  }
}

// === GLOBAL INITIALIZATION ===
let messagingInstance = null;

export async function initializeMessaging() {
  if (messagingInstance) {
    return messagingInstance;
  }

  messagingInstance = new NitoMessaging();
  return messagingInstance;
}

// === GLOBAL EXPORTS ===
if (typeof window !== 'undefined') {
  window.messaging = null;
  window.initializeMessaging = initializeMessaging;
  window.NitoMessaging = NitoMessaging;
  
  window.clearMessagingCaches = () => {
    if (window.messaging) {
      window.messaging.clearCaches();
    }
  };
}

// === INITIALIZATION ===
(async () => {
  try {
    messagingInstance = await initializeMessaging();
    window.messaging = messagingInstance;
    
    const waitForDOM = () => {
      if (document.readyState === 'loading') {
        return new Promise(resolve => document.addEventListener('DOMContentLoaded', resolve));
      }
      return Promise.resolve();
    };
    
    await waitForDOM();
    
    const cancelButton = document.getElementById('cancelSendButton');
    if (cancelButton) {
      cancelButton.addEventListener('click', () => {
        const form = document.getElementById('sendMessageForm');
        if (form) {
          form.style.display = 'none';
          if (window.messaging) {
            window.messaging.formIsOpen = false;
          }
        }
      });
    }
    
    const confirmButton = document.getElementById('confirmSendButton');
    if (confirmButton) {
      confirmButton.addEventListener('click', async () => {
        if (window.messaging) {
          await window.messaging.sendMessage();
        }
      });
    }
    
  } catch (error) {
    console.error('[MESSAGING] Init failed:', error);
  }
})();

export default NitoMessaging;