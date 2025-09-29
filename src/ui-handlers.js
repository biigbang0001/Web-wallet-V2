// UI Event Handlers for NITO Wallet

import { ELEMENT_IDS, FEATURE_FLAGS } from './config.js';
import { copyToClipboard, armInactivityTimerSafely } from './security.js';
import { eventBus, EVENTS } from './events.js';

// === EVENT HANDLER DEDUPLICATION ===
const handlerRegistry = new Map();
let setupComplete = false;
let isMaxButtonUsed = false;

function addUniqueEventListener(elementId, eventType, handler, options = {}) {
  const element = document.getElementById(elementId);
  if (!element) {
    console.warn(`[UI] Element not found: ${elementId}`);
    return false;
  }

  const key = `${elementId}:${eventType}`;
  
  if (handlerRegistry.has(key)) {
    const oldHandler = handlerRegistry.get(key);
    element.removeEventListener(eventType, oldHandler);
    handlerRegistry.delete(key);
  }

  element.addEventListener(eventType, handler, options);
  handlerRegistry.set(key, handler);
  
  return true;
}

function removeEventListener(elementId, eventType) {
  const element = document.getElementById(elementId);
  const key = `${elementId}:${eventType}`;
  
  if (handlerRegistry.has(key)) {
    const handler = handlerRegistry.get(key);
    if (element) {
      element.removeEventListener(eventType, handler);
    }
    handlerRegistry.delete(key);
    console.log(`[UI] Handler removed: ${key}`);
  }
}

function setButtonLoading(buttonId, loading, originalText = null) {
  const button = document.getElementById(buttonId);
  if (!button) return;
  
  const t = window.getTranslation || ((key, fallback) => fallback || key);
  
  if (loading) {
    if (!button.dataset.originalText) {
      button.dataset.originalText = button.textContent;
    }
    button.innerHTML = t('loading.refreshing', 'Refreshing...');
    button.disabled = true;
    button.style.opacity = '0.7';
  } else {
    const text = originalText || button.dataset.originalText;
    if (text) {
      button.textContent = text;
    } else {
      const refreshText = t('import_section.refresh_button', 'Refresh');
      button.textContent = refreshText;
    }
    button.disabled = false;
    button.style.opacity = '1';
    delete button.dataset.originalText;
  }
}

function hideAllAuthForms() {
  const emailForm = document.getElementById('emailForm');
  const keyForm = document.getElementById('keyForm');
  const tabEmail = document.getElementById('tabEmail');
  const tabKey = document.getElementById('tabKey');
  
  if (emailForm) emailForm.style.display = 'none';
  if (keyForm) keyForm.style.display = 'none';
  if (tabEmail) tabEmail.style.display = 'none';
  if (tabKey) tabKey.style.display = 'none';
}

function clearInputFields() {
  const privateKeyField = document.getElementById(ELEMENT_IDS.PRIVATE_KEY_WIF);
  const emailField = document.getElementById(ELEMENT_IDS.EMAIL_INPUT);
  const passwordField = document.getElementById(ELEMENT_IDS.PASSWORD_INPUT);
  
  if (privateKeyField) {
    privateKeyField.value = '';
    privateKeyField.style.filter = 'blur(4px)';
  }
  if (emailField) emailField.value = '';
  if (passwordField) passwordField.value = '';
}

function updateAddressSelector(importType) {
  const selector = document.getElementById(ELEMENT_IDS.DEBIT_ADDRESS_TYPE);
  if (!selector) return;

  const currentValue = selector.value;
  selector.innerHTML = '';
  
  if (importType === 'hd' || importType === 'email' || importType === 'mnemonic' || importType === 'xprv') {
    const bech32Option = document.createElement('option');
    bech32Option.value = 'bech32';
    bech32Option.selected = true;
    bech32Option.setAttribute('data-i18n', 'send_section.bech32_option');
    bech32Option.textContent = 'Bech32';
    selector.appendChild(bech32Option);
    
    const taprootOption = document.createElement('option');
    taprootOption.value = 'p2tr';
    taprootOption.textContent = 'Bech32m (Taproot)';
    selector.appendChild(taprootOption);
    
    if (currentValue === 'p2tr') {
      selector.value = 'p2tr';
    } else {
      selector.value = 'bech32';
    }
  } else {
    const bech32Option = document.createElement('option');
    bech32Option.value = 'bech32';
    bech32Option.selected = true;
    bech32Option.setAttribute('data-i18n', 'send_section.bech32_option');
    bech32Option.textContent = 'Bech32';
    selector.appendChild(bech32Option);
  }
}

function displayWalletInfo(addresses, importType, onBalanceUpdated) {
  armInactivityTimerSafely();
  
  const walletAddressElement = document.getElementById(ELEMENT_IDS.WALLET_ADDRESS);
  const bech32Element = document.getElementById(ELEMENT_IDS.BECH32_ADDRESS);
  const taprootElement = document.getElementById(ELEMENT_IDS.TAPROOT_ADDRESS);
  const addressesSection = document.getElementById('nito-addresses');
  
  if (walletAddressElement && addresses) {
    const t = window.getTranslation || ((key, fallback) => fallback || key);
    const balanceText = t('import_section.balance', 'Balance:');
    
    if (importType === 'hd' || importType === 'email' || importType === 'mnemonic' || importType === 'xprv') {
      walletAddressElement.innerHTML = `
        <div style="margin-top: 10px;">
          <strong>Bech32:</strong> ${addresses.bech32}<br>
          <strong>Taproot:</strong> ${addresses.taproot}
        </div>
        <div id="totalBalance" style="margin-top: 10px; font-weight: bold; color: #2196F3;">
          ${balanceText} 0.00000000 NITO
        </div>
      `;
    } else {
      walletAddressElement.innerHTML = `
        <div style="margin-top: 10px;">
          <strong>Bech32:</strong> ${addresses.bech32}
        </div>
        <div id="totalBalance" style="margin-top: 10px; font-weight: bold; color: #2196F3;">
          ${balanceText} 0.00000000 NITO
        </div>
      `;
    }
    
    if (addressesSection) {
      addressesSection.style.display = 'block';
      if (bech32Element) bech32Element.value = addresses.bech32 || '';
      if (taprootElement) taprootElement.value = addresses.taproot || '';
    }
  }
  
  updateAddressSelector(importType);
  injectConsolidateButton();
  
  setTimeout(async () => {
    try {
      if (window.getTotalBalance) {
        const total = await window.getTotalBalance();
        const balanceElement = document.getElementById('totalBalance');
        if (balanceElement) {
          const t = window.getTranslation || ((key, fallback) => fallback || key);
          const balanceText = t('import_section.balance', 'Balance:');
          balanceElement.textContent = `${balanceText} ${total.toFixed(8)} NITO`;
        }
      }
      if (onBalanceUpdated) onBalanceUpdated();
    } catch (error) {
      console.error('[UI] Auto balance update error:', error);
      if (onBalanceUpdated) onBalanceUpdated();
    }
  }, 1000);
}

function injectConsolidateButton() {
  const consolidateContainer = document.querySelector('.consolidate-container');
  if (consolidateContainer && !consolidateContainer.querySelector('#consolidateButton')) {
    const t = window.getTranslation || ((key, fallback) => fallback || key);
      
    const consolidateButton = document.createElement('button');
    consolidateButton.id = 'consolidateButton';
    consolidateButton.className = 'consolidate-button';
    consolidateButton.type = 'button';
    consolidateButton.setAttribute('data-i18n','consolidate.cta'); 
    consolidateButton.textContent = t('consolidate.cta', 'Consolidate UTXOs');
    consolidateButton.style.display = 'inline-block';
    consolidateButton.style.marginTop = '10px';
    
    consolidateButton.addEventListener('click', async () => {
      armInactivityTimerSafely();
      
      if (window.isOperationActive && window.isOperationActive('consolidation')) {
        return;
      }
      
      if (window.consolidateUtxos) {
        await window.consolidateUtxos();
        setTimeout(() => {
          if (window.refreshAllBalances) {
            window.refreshAllBalances();
          }
        }, 3000);
      } else {
        const t = window.getTranslation || ((key, fallback) => fallback || key);
        const errorMsg = t('errors.consolidation_unavailable', 'Consolidation function unavailable');
        alert(errorMsg);
      }
    });
    
    consolidateContainer.appendChild(consolidateButton);
  }
}

function createSecureSeedButton(mnemonic, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const t = window.getTranslation || ((key, fallback) => fallback || key);

  const existingSeedButton = document.getElementById(ELEMENT_IDS.EMAIL_SEED_BUTTON);
  if (existingSeedButton) {
    existingSeedButton.remove();
  }

  const seedButton = document.createElement('button');
  seedButton.id = ELEMENT_IDS.EMAIL_SEED_BUTTON;
  seedButton.className = 'reveal-btn';
  seedButton.textContent = t('seed_reveal.button_reveal', 'Reveal mnemonic phrase');
  seedButton.style.marginTop = '10px';
  seedButton.style.display = 'block';

  let isRevealed = false;
  let revealTimeout = null;

  seedButton.addEventListener('click', () => {
    armInactivityTimerSafely();
    
    if (!isRevealed) {
      const seedDisplay = document.createElement('div');
      seedDisplay.id = 'tempSeedDisplay';
      seedDisplay.style.cssText = `
        margin: 10px 0; 
        padding: 15px; 
        background: rgba(var(--glass-bg), 0.1); 
        border: 1px solid var(--glass-border); 
        border-radius: 12px; 
        font-family: monospace; 
        word-break: break-all; 
        border-left: 4px solid #4caf50;
        position: relative;
      `;
      
      const warningText = t('seed_reveal.warning_title', 'Mnemonic phrase (24 words):');
      const copyButtonText = t('seed_reveal.copy_button', 'Copy');
      const timeoutWarning = t('seed_reveal.timeout_warning', 'This phrase will automatically be hidden in 30 seconds');
      
      seedDisplay.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 8px;">${warningText}</div>
        <div style="background: rgba(0,0,0,0.05); padding: 8px; border-radius: 6px; margin-bottom: 8px;">${mnemonic}</div>
        <button id="copySeedBtn" class="copy-btn" style="margin-right: 8px;">${copyButtonText}</button>
        <small style="color: var(--text-secondary); font-size: 0.85em;">
          ${timeoutWarning}
        </small>
      `;

      container.appendChild(seedDisplay);

      document.getElementById('copySeedBtn').addEventListener('click', () => {
        armInactivityTimerSafely();
        
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(mnemonic).then(() => {
            const successMsg = t('seed_reveal.copy_success', 'Mnemonic phrase copied to clipboard!');
            alert(successMsg);
          }).catch(() => {
            const textArea = document.createElement('textarea');
            textArea.value = mnemonic;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            const fallbackMsg = t('seed_reveal.copy_fallback', 'Mnemonic phrase copied!');
            alert(fallbackMsg);
          });
        }
      });

      seedButton.textContent = t('seed_reveal.button_hide', 'Hide phrase');
      isRevealed = true;

      revealTimeout = setTimeout(() => {
        hideSeed();
      }, 30000);

    } else {
      hideSeed();
    }
  });

  function hideSeed() {
    const seedDisplay = document.getElementById('tempSeedDisplay');
    if (seedDisplay) {
      seedDisplay.remove();
    }
    seedButton.textContent = t('seed_reveal.button_reveal', 'Reveal mnemonic phrase');
    isRevealed = false;
    
    if (revealTimeout) {
      clearTimeout(revealTimeout);
      revealTimeout = null;
    }
  }

  container.appendChild(seedButton);
  return seedButton;
}

// === GENERATION HANDLERS ===
function setupGenerationHandlers() {
  addUniqueEventListener(ELEMENT_IDS.GENERATE_BUTTON, 'click', async () => {
    armInactivityTimerSafely();
    
    if (window.isOperationActive && window.isOperationActive('generation')) {
      return;
    }
    
    const t = window.getTranslation || ((key, fallback) => fallback || key);
      
    try {
      if (window.startOperation) window.startOperation('generation');
      if (window.showBalanceLoadingSpinner) window.showBalanceLoadingSpinner(true, 'loading.wallet_setup');
      setButtonLoading(ELEMENT_IDS.GENERATE_BUTTON, true);
      
      armInactivityTimerSafely();

      if (window.hdManager) {
        const mnemonic = await window.hdManager.generateMnemonic(24);
        const addresses = await window.hdManager.importHDWallet(mnemonic);
        
        document.getElementById(ELEMENT_IDS.HD_MASTER_KEY).textContent = addresses.hdMasterKey || '';
        document.getElementById(ELEMENT_IDS.MNEMONIC_PHRASE).textContent = addresses.mnemonic || '';
        document.getElementById(ELEMENT_IDS.GENERATED_ADDRESS).innerHTML = `
          <strong>Bech32:</strong> ${addresses.bech32}<br>
          <strong>Taproot:</strong> ${addresses.taproot}
        `;

        try {
          await fetch('/api/get-counter.php', { method: 'POST' });
          const response = await fetch('/api/get-counter.php');
          const data = await response.json();
          document.getElementById(ELEMENT_IDS.KEY_COUNTER).textContent = data.count || 0;
        } catch (e) {
          console.warn('[UI] Counter update failed:', e);
        }

        console.log('HD wallet generated (24 words):', {
          bech32: addresses.bech32,
          taproot: addresses.taproot,
          legacy: addresses.legacy,
          p2sh: addresses.p2sh
        });
      }
    } catch (error) {
      const errorMsg = t('errors.generation_failed', `Generation error: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Generation error:', error);
    } finally {
      if (window.showBalanceLoadingSpinner) window.showBalanceLoadingSpinner(false);
      setButtonLoading(ELEMENT_IDS.GENERATE_BUTTON, false);
      if (window.endOperation) window.endOperation('generation');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.COPY_HD_KEY, 'click', () => {
    armInactivityTimerSafely();
    copyToClipboard(ELEMENT_IDS.HD_MASTER_KEY);
  });

  addUniqueEventListener(ELEMENT_IDS.COPY_MNEMONIC, 'click', () => {
    armInactivityTimerSafely();
    copyToClipboard(ELEMENT_IDS.MNEMONIC_PHRASE);
  });
}

// === IMPORT HANDLERS ===
function setupImportHandlers() {
  addUniqueEventListener(ELEMENT_IDS.IMPORT_WALLET_BUTTON, 'click', async () => {
    armInactivityTimerSafely();
    
    if (window.isOperationActive && window.isOperationActive('import')) {
      return;
    }
    
    const t = window.getTranslation || ((key, fallback) => fallback || key);
      
    try {
      if (window.startOperation) window.startOperation('import');
      if (window.showBalanceLoadingSpinner) window.showBalanceLoadingSpinner(true, 'loading.importing_wallet');
      setButtonLoading(ELEMENT_IDS.IMPORT_WALLET_BUTTON, true);
      
      const input = document.getElementById(ELEMENT_IDS.PRIVATE_KEY_WIF)?.value?.trim();
      if (!input) {
        const errorMsg = t('errors.enter_key', 'Please enter a private key, mnemonic or XPRV');
        alert(errorMsg);
        return;
      }

      const result = await window.importWallet(input);
      
      if (result.success) {
        displayWalletInfo(result.addresses, result.importType, () => {
          if (window.showBalanceLoadingSpinner) window.showBalanceLoadingSpinner(false);
        });
        hideAllAuthForms();
        clearInputFields();
        
        console.log('Wallet imported successfully:', result.importType);
      } else {
        const errorMsg = t('errors.import_failed', `Import failed: ${result.error}`);
        alert(errorMsg);
        if (window.showBalanceLoadingSpinner) window.showBalanceLoadingSpinner(false);
      }
    } catch (error) {
      const errorMsg = t('errors.import_error', `Import error: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Import error:', error);
      if (window.showBalanceLoadingSpinner) window.showBalanceLoadingSpinner(false);
    } finally {
      setButtonLoading(ELEMENT_IDS.IMPORT_WALLET_BUTTON, false);
      if (window.endOperation) window.endOperation('import');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.CONNECT_EMAIL_BUTTON, 'click', async () => {
    armInactivityTimerSafely();
    
    if (window.isOperationActive && window.isOperationActive('email-connect')) {
      return;
    }
    
    const t = window.getTranslation || ((key, fallback) => fallback || key);
      
    try {
      if (window.startOperation) window.startOperation('email-connect');
      if (window.showBalanceLoadingSpinner) window.showBalanceLoadingSpinner(true, 'loading.connecting_email');
      setButtonLoading(ELEMENT_IDS.CONNECT_EMAIL_BUTTON, true);
      
      const email = document.getElementById(ELEMENT_IDS.EMAIL_INPUT)?.value?.trim();
      const password = document.getElementById(ELEMENT_IDS.PASSWORD_INPUT)?.value?.trim();
      
      if (!email || !password) {
        const errorMsg = t('errors.enter_email_password', 'Please enter email and password');
        alert(errorMsg);
        return;
      }
      
      const result = await window.importWallet(email, password);
      
      if (result.success) {
        displayWalletInfo(result.addresses, result.importType, () => {
          if (window.showBalanceLoadingSpinner) window.showBalanceLoadingSpinner(false);
        });
        hideAllAuthForms();
        clearInputFields();

        if (result.mnemonic) {
          createSecureSeedButton(result.mnemonic, 'emailForm');
        }
        
      } else {
        const errorMsg = t('errors.connection_failed', `Connection failed: ${result.error}`);
        alert(errorMsg);
        if (window.showBalanceLoadingSpinner) window.showBalanceLoadingSpinner(false);
      }
    } catch (error) {
      const errorMsg = t('errors.connection_error', `Connection error: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Connection error:', error);
      if (window.showBalanceLoadingSpinner) window.showBalanceLoadingSpinner(false);
    } finally {
      setButtonLoading(ELEMENT_IDS.CONNECT_EMAIL_BUTTON, false);
      if (window.endOperation) window.endOperation('email-connect');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.REFRESH_BALANCE_BUTTON, 'click', async () => {
    armInactivityTimerSafely();
    
    try {
      setButtonLoading(ELEMENT_IDS.REFRESH_BALANCE_BUTTON, true);
      if (window.refreshAllBalances) {
        await window.refreshAllBalances();
      }
    } catch (error) {
      console.error('[UI] Refresh balance error:', error);
    } finally {
      setButtonLoading(ELEMENT_IDS.REFRESH_BALANCE_BUTTON, false);
    }
  });
}

// === AUTHENTICATION SYSTEM ===
function setupAuthenticationSystem() {
  const tabEmail = document.getElementById('tabEmail');
  const tabKey = document.getElementById('tabKey');
  const emailForm = document.getElementById('emailForm');
  const keyForm = document.getElementById('keyForm');

  if (tabEmail && tabKey && emailForm && keyForm) {
    addUniqueEventListener('tabEmail', 'click', () => {
      armInactivityTimerSafely();
      
      tabEmail.classList.add('active');
      tabKey.classList.remove('active');
      emailForm.classList.add('active');
      keyForm.classList.remove('active');
      emailForm.style.display = 'block';
      keyForm.style.display = 'none';
      
      tabKey.style.display = 'block';
      tabEmail.style.display = 'block';
    });
    
    addUniqueEventListener('tabKey', 'click', () => {
      armInactivityTimerSafely();
      
      tabKey.classList.add('active');
      tabEmail.classList.remove('active');
      keyForm.classList.add('active');
      emailForm.classList.remove('active');
      keyForm.style.display = 'block';
      emailForm.style.display = 'none';
      
      tabEmail.style.display = 'block';
      tabKey.style.display = 'block';
    });
  }
}

// === TRANSACTION HANDLERS ===
function setupTransactionHandlers() {
  const t = window.getTranslation || ((key, fallback) => fallback || key);
    
  addUniqueEventListener(ELEMENT_IDS.MAX_BUTTON, 'click', async () => {
    armInactivityTimerSafely();
    
    const maxButton = document.getElementById(ELEMENT_IDS.MAX_BUTTON);
    const amtEl = document.getElementById(ELEMENT_IDS.AMOUNT_NITO);
    
    if (maxButton) {
      maxButton.disabled = true;
      const calculatingText = t('ui.calculating', 'Calculating...');
      maxButton.textContent = calculatingText;
    }
    
    try {
      if (!window.isWalletReady || !window.isWalletReady()) {
        const errorMsg = t('errors.import_first', 'Import a wallet first.');
        alert(errorMsg);
        return;
      }

      if (!window.calculateMaxSendableAmount) {
        const msg = t('ui.max_function_unavailable', 'calculateMaxSendableAmount function unavailable');
        throw new Error(msg);
      }

      const maxAmount = await window.calculateMaxSendableAmount();
      
      if (amtEl) {
        amtEl.value = maxAmount.toFixed(8);
        isMaxButtonUsed = true;
      }
      
    } catch (error) {
      console.error('[UI] MAX computation error:', error);
      if (amtEl) amtEl.value = '0.00000000';
      
      const errorMsg = t('ui.max_calculation_error', `MAX calculation error: ${error.message}`);
      alert(errorMsg);
    } finally {
      if (maxButton) {
        maxButton.disabled = false;
        maxButton.textContent = 'MAX';
      }
    }
  });

  addUniqueEventListener(ELEMENT_IDS.AMOUNT_NITO, 'input', () => {
    isMaxButtonUsed = false;
  });

  addUniqueEventListener(ELEMENT_IDS.PREPARE_TX_BUTTON, 'click', async () => {
    armInactivityTimerSafely();
    
    if (window.isOperationActive && window.isOperationActive('transaction')) {
      return;
    }
    
    const t = window.getTranslation || ((key, fallback) => fallback || key);
    
    try {
      if (window.startOperation) window.startOperation('transaction');
      if (window.showBalanceLoadingSpinner) {
        window.showBalanceLoadingSpinner(true, 'loading.preparing_transaction');
      }
      setButtonLoading(ELEMENT_IDS.PREPARE_TX_BUTTON, true);
      
      const to = document.getElementById(ELEMENT_IDS.DESTINATION_ADDRESS)?.value?.trim();
      const amount = parseFloat(document.getElementById(ELEMENT_IDS.AMOUNT_NITO)?.value || '0');
      
      if (!to) {
        const msg = t('ui.enter_destination_address', 'Please enter a destination address');
        throw new Error(msg);
      }
      
      if (!amount || amount <= 0) {
        const msg = t('ui.invalid_amount', 'Invalid amount');
        throw new Error(msg);
      }
      
      if (!window.signTxWithPSBT) {
        const msg = t('errors.transaction_functions_unavailable', 'Transaction functions unavailable');
        throw new Error(msg);
      }
      
      console.log('[TX-PREP] Creating transaction via transactions.js...');
      
      const result = await window.signTxWithPSBT(to, amount, false, { isMaxSend: isMaxButtonUsed });
      
      document.getElementById(ELEMENT_IDS.SIGNED_TX).textContent = result.hex;
      document.getElementById(ELEMENT_IDS.TX_HEX_CONTAINER).style.display = 'block';
      
      document.getElementById(ELEMENT_IDS.BROADCAST_TX_BUTTON).style.display = 'inline-block';
      document.getElementById(ELEMENT_IDS.CANCEL_TX_BUTTON).style.display = 'inline-block';
      
      console.log('[TX-PREP] Transaction prepared successfully');
      isMaxButtonUsed = false;
      
    } catch (error) {
      const errorMsg = t('errors.transaction_prep_failed', `Transaction preparation failed: ${error.message}`);
      alert(errorMsg);
      console.error('[TX-PREP] Transaction preparation error:', error);
      isMaxButtonUsed = false;
    } finally {
      if (window.showBalanceLoadingSpinner) {
        window.showBalanceLoadingSpinner(false);
      }
      setButtonLoading(ELEMENT_IDS.PREPARE_TX_BUTTON, false);
      if (window.endOperation) window.endOperation('transaction');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.BROADCAST_TX_BUTTON, 'click', async () => {
    armInactivityTimerSafely();
    
    if (window.isOperationActive && window.isOperationActive('broadcast')) {
      return;
    }
    
    const t = window.getTranslation || ((key, fallback) => fallback || key);
    
    try {
      if (window.startOperation) window.startOperation('broadcast');
      if (window.showBalanceLoadingSpinner) {
        window.showBalanceLoadingSpinner(true, 'loading.broadcasting');
      }
      setButtonLoading(ELEMENT_IDS.BROADCAST_TX_BUTTON, true);
      
      const hex = document.getElementById(ELEMENT_IDS.SIGNED_TX)?.textContent;
      if (!hex) {
        const errorMsg = t('errors.no_transaction', 'No transaction to broadcast');
        alert(errorMsg);
        return;
      }
      
      if (!window.rpc) {
        const errorMsg = t('errors.rpc_unavailable', 'RPC function unavailable');
        throw new Error(errorMsg);
      }
      
      const txid = await window.rpc('sendrawtransaction', [hex]);
      
      if (window.showSuccessPopup) {
        await window.showSuccessPopup(txid);
      }
      
      document.getElementById(ELEMENT_IDS.DESTINATION_ADDRESS).value = '';
      document.getElementById(ELEMENT_IDS.AMOUNT_NITO).value = '';
      document.getElementById(ELEMENT_IDS.TX_HEX_CONTAINER).style.display = 'none';
      document.getElementById(ELEMENT_IDS.BROADCAST_TX_BUTTON).style.display = 'none';
      document.getElementById(ELEMENT_IDS.CANCEL_TX_BUTTON).style.display = 'none';
      
    } catch (error) {
      const errorMsg = t('errors.broadcast_failed', `Broadcast failed: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Broadcast error:', error);
    } finally {
      if (window.showBalanceLoadingSpinner) {
        window.showBalanceLoadingSpinner(false);
      }
      setButtonLoading(ELEMENT_IDS.BROADCAST_TX_BUTTON, false);
      if (window.endOperation) window.endOperation('broadcast');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.CANCEL_TX_BUTTON, 'click', () => {
    armInactivityTimerSafely();
    
    document.getElementById(ELEMENT_IDS.TX_HEX_CONTAINER).style.display = 'none';
    document.getElementById(ELEMENT_IDS.BROADCAST_TX_BUTTON).style.display = 'none';
    document.getElementById(ELEMENT_IDS.CANCEL_TX_BUTTON).style.display = 'none';
    document.getElementById(ELEMENT_IDS.SIGNED_TX).textContent = '';
    isMaxButtonUsed = false;
  });

  addUniqueEventListener(ELEMENT_IDS.COPY_TX_HEX, 'click', () => {
    armInactivityTimerSafely();
    copyToClipboard(ELEMENT_IDS.SIGNED_TX);
  });

  addUniqueEventListener(ELEMENT_IDS.REFRESH_SEND_TAB_BALANCE, 'click', async () => {
    armInactivityTimerSafely();
    
    try {
      setButtonLoading(ELEMENT_IDS.REFRESH_SEND_TAB_BALANCE, true);
      if (window.refreshAllBalances) {
        await window.refreshAllBalances();
      }
    } catch (error) {
      console.error('[UI] Send tab balance refresh error:', error);
    } finally {
      setButtonLoading(ELEMENT_IDS.REFRESH_SEND_TAB_BALANCE, false);
    }
  });
}

// === MAIN SETUP FUNCTION ===
export function setupUIHandlers() {
  if (setupComplete) {
    return true;
  }
  
  try {
    setupGenerationHandlers();
    setupImportHandlers();
    setupAuthenticationSystem();
    setupTransactionHandlers();
    
    setupComplete = true;
    return true;
  } catch (error) {
    console.error('[UI] Handlers setup failed:', error);
    setupComplete = false;
    return false;
  }
}

export function cleanupUIHandlers() {
  handlerRegistry.forEach((handler, key) => {
    const [elementId, eventType] = key.split(':');
    removeEventListener(elementId, eventType);
  });
  
  handlerRegistry.clear();
  setupComplete = false;
}

function initializeWhenReady() {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(setupUIHandlers, 100);
    });
  } else {
    setTimeout(setupUIHandlers, 100);
  }
}

if (typeof window !== 'undefined') {
  if (window.i18next && typeof window.i18next.on === 'function') {
    window.i18next.on('languageChanged', () => {
      setTimeout(() => {
        const buttons = document.querySelectorAll('button[data-i18n]');
        buttons.forEach(btn => {
          const key = btn.getAttribute('data-i18n');
          if (key && window.i18next) {
            const text = window.i18next.t(key);
            if (text && text !== key) {
              btn.textContent = text;
            }
          }
        });
      }, 100);
    });
  }
}

initializeWhenReady();

if (typeof window !== 'undefined') {
  window.setupUIHandlers = setupUIHandlers;
  window.cleanupUIHandlers = cleanupUIHandlers;
  window.addUniqueEventListener = addUniqueEventListener;
  window.removeEventListener = removeEventListener;
  window.displayWalletInfo = displayWalletInfo;
  window.updateAddressSelector = updateAddressSelector;
  window.hideAllAuthForms = hideAllAuthForms;
  window.clearInputFields = clearInputFields;
  window.createSecureSeedButton = createSecureSeedButton;
}

console.log('UI handlers module loaded - Version 2.0.0');