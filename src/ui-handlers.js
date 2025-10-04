import { ELEMENT_IDS, FEATURE_FLAGS, SECURITY_CONFIG, getTranslation } from './config.js';
import { armInactivityTimerSafely, revealElement, blurElement, copyToClipboard as securityCopy } from './security.js';
import { eventBus, EVENTS } from './events.js';
import { 
    showSuccessPopup, 
    showConsolidationConfirmPopup,
    showLoading,
    hideLoading,
    showBalanceLoadingSpinner,
    showCopyFeedback
} from './ui-popups.js';

const handlerRegistry = new Map();
let setupComplete = false;
let isMaxButtonUsed = false;

// === RATE LIMITING FOR NON-REFRESH BUTTONS ===
const buttonCooldowns = new Map();

function isButtonOnCooldown(buttonId, cooldownMs) {
  const now = Date.now();
  const lastClick = buttonCooldowns.get(buttonId) || 0;
  
  if (now - lastClick < cooldownMs) {
    return true;
  }
  
  buttonCooldowns.set(buttonId, now);
  return false;
}

// === CLIPBOARD OPERATIONS ===
export async function copyToClipboard(elementId) {
  try {
    const result = await securityCopy(elementId, { isElementId: true });
    showCopyFeedback(result.success);
  } catch (error) {
    console.error('[UI] Copy error:', error);
    showCopyFeedback(false, error.message);
  }
}

// === EVENT LISTENER MANAGEMENT ===
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
  }
}

// === BUTTON LOADING STATE ===
export function setButtonLoading(buttonId, loading, originalText = null) {
  const button = document.getElementById(buttonId);
  if (!button) return;
  
  if (loading) {
    if (!button.dataset.originalText) {
      button.dataset.originalText = button.textContent;
    }
    button.innerHTML = getTranslation('loading.refreshing', 'Refreshing...');
    button.disabled = true;
    button.style.opacity = '0.7';
  } else {
    const text = originalText || button.dataset.originalText;
    if (text) {
      button.textContent = text;
    } else {
      const refreshText = getTranslation('import_section.refresh_button', 'Refresh');
      button.textContent = refreshText;
    }
    button.disabled = false;
    button.style.opacity = '1';
    delete button.dataset.originalText;
  }
}

// === FORM VISIBILITY MANAGEMENT ===
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

// === ADDRESS TYPE SELECTOR ===
export function updateAddressSelector(importType) {
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

// === WALLET INFO DISPLAY ===
export function displayWalletInfo(addresses, importType, onBalanceUpdated) {
  armInactivityTimerSafely();
  
  const walletAddressElement = document.getElementById(ELEMENT_IDS.WALLET_ADDRESS);
  const bech32Element = document.getElementById(ELEMENT_IDS.BECH32_ADDRESS);
  const taprootElement = document.getElementById(ELEMENT_IDS.TAPROOT_ADDRESS);
  const addressesSection = document.getElementById('nito-addresses');
  
  if (walletAddressElement && addresses) {
    const balanceText = getTranslation('import_section.balance', 'Balance:');
    
    if (importType === 'hd' || importType === 'email' || importType === 'mnemonic' || importType === 'xprv') {
      walletAddressElement.innerHTML = `
        <div style="margin-top: 10px;">
          <strong>Bech32:</strong> ${addresses.bech32}<br>
          <strong>Taproot:</strong> ${addresses.taproot}
        </div>
        <div id="totalBalance" style="margin-top: 10px; font-weight: bold; color: #2196F3;">
          ${balanceText} <span class="loading-dots">...</span>
        </div>
        <div id="credentialsButtonsContainer" style="margin-top: 15px;"></div>
      `;
    } else {
      walletAddressElement.innerHTML = `
        <div style="margin-top: 10px;">
          <strong>Bech32:</strong> ${addresses.bech32}
        </div>
        <div id="totalBalance" style="margin-top: 10px; font-weight: bold; color: #2196F3;">
          ${balanceText} <span class="loading-dots">...</span>
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
  
  const refreshContainer = document.getElementById('refreshBalanceContainer');
  if (refreshContainer) refreshContainer.style.display = 'block';
  
  const refreshBtn = document.getElementById(ELEMENT_IDS.REFRESH_BALANCE_BUTTON);
  if (refreshBtn) refreshBtn.style.display = 'inline-block';
  
  if (onBalanceUpdated) {
    setTimeout(() => {
      onBalanceUpdated();
    }, 500);
  }
}

// === CONSOLIDATE BUTTON INJECTION ===
function injectConsolidateButton() {
  const consolidateContainer = document.querySelector('.consolidate-container');
  if (consolidateContainer && !consolidateContainer.querySelector('#consolidateButton')) {
      
    const consolidateButton = document.createElement('button');
    consolidateButton.id = 'consolidateButton';
    consolidateButton.className = 'consolidate-button';
    consolidateButton.type = 'button';
    consolidateButton.setAttribute('data-i18n','consolidate.cta'); 
    consolidateButton.textContent = getTranslation('consolidate.cta', 'Consolidate UTXOs');
    consolidateButton.style.display = 'inline-block';
    consolidateButton.style.marginTop = '10px';
    
    consolidateButton.addEventListener('click', async () => {
      if (isButtonOnCooldown('consolidateButton', 10000)) return;
      
      armInactivityTimerSafely();
      
      if (window.isOperationActive && window.isOperationActive('consolidation')) {
        return;
      }
      
      if (window.consolidateUTXOs) {
        await window.consolidateUTXOs();
        setTimeout(() => {
          if (window.refreshAllBalances) {
            window.refreshAllBalances();
          }
        }, 3000);
      } else {
        const errorMsg = getTranslation('errors.consolidation_unavailable', 'Consolidation function unavailable');
        alert(errorMsg);
      }
    });
    
    consolidateContainer.appendChild(consolidateButton);
  }
}

// === SECURE CREDENTIALS BUTTONS ===
export function createSecureCredentialsButtons(_, __, containerId) {
  const container = document.getElementById(containerId);
  if (!container) {
    console.warn('[UI] Container not found:', containerId);
    return;
  }

  const oldSeedButton = document.getElementById(ELEMENT_IDS.EMAIL_SEED_BUTTON);
  const oldXprvButton = document.getElementById('emailXprvButton');
  if (oldSeedButton) oldSeedButton.remove();
  if (oldXprvButton) oldXprvButton.remove();

  const seedButton = document.createElement('button');
  seedButton.id = ELEMENT_IDS.EMAIL_SEED_BUTTON;
  seedButton.className = 'copy-btn';
  const revealText = getTranslation('generate_section.reveal', 'Reveal');
  seedButton.textContent = revealText + ' Mnemonic';
  seedButton.style.marginTop = '10px';
  seedButton.style.display = 'block';

  let mnemonicRevealed = false;
  let mnemonicTimeout = null;

  seedButton.addEventListener('click', async () => {
    armInactivityTimerSafely();
    
    if (!mnemonicRevealed) {
      if (!window.keyManager) {
        alert('KeyManager not available');
        return;
      }

      const mnemonic = await window.keyManager.retrieveKey('mnemonic');
      if (!mnemonic) {
        alert('Mnemonic not available');
        return;
      }
      
      const seedDisplay = document.createElement('div');
      seedDisplay.id = 'tempSeedDisplay';
      seedDisplay.style.cssText = `
        margin: 10px 0; 
        padding: 15px; 
        background: var(--glass-bg); 
        border: 1px solid var(--glass-border); 
        border-radius: 12px; 
        font-family: monospace; 
        word-break: break-all; 
        border-left: 4px solid #4caf50;
        position: relative;
      `;
      
      const mnemonicTitle = getTranslation('generate_section.hd_mnemonic_title', 'HD MNEMONIC SEED (24 words):');
      const warningText = getTranslation('generate_section.warning', 'Save the private key immediately!');
      const copyButtonText = getTranslation('generate_section.copy', 'Copy');
      const cancelText = getTranslation('send_section.cancel_button', 'Cancel');
      
      seedDisplay.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 8px;">${mnemonicTitle}</div>
        <div class="blurred" id="mnemonicContent" style="background: rgba(0,0,0,0.05); padding: 8px; border-radius: 6px; margin-bottom: 8px; cursor: pointer;">${mnemonic}</div>
        <button id="revealMnemonicBtn" class="reveal-btn" style="margin-right: 8px;">${revealText}</button>
        <button id="copyMnemonicBtn" class="copy-btn" style="margin-right: 8px;">${copyButtonText}</button>
        <small style="color: var(--text-secondary); font-size: 0.85em;">
          ${warningText}
        </small>
      `;

      container.appendChild(seedDisplay);

      document.getElementById('revealMnemonicBtn').addEventListener('click', () => {
        armInactivityTimerSafely();
        const content = document.getElementById('mnemonicContent');
        if (content) content.classList.toggle('blurred');
      });

      document.getElementById('copyMnemonicBtn').addEventListener('click', async () => {
        armInactivityTimerSafely();
        try {
          await securityCopy(mnemonic, { isElementId: false });
          showCopyFeedback(true);
        } catch (error) {
          showCopyFeedback(false, error.message);
        }
      });

      seedButton.textContent = cancelText;
      mnemonicRevealed = true;

      mnemonicTimeout = setTimeout(() => {
        hideMnemonic();
      }, 30000);

    } else {
      hideMnemonic();
    }
  });

  function hideMnemonic() {
    const seedDisplay = document.getElementById('tempSeedDisplay');
    if (seedDisplay) seedDisplay.remove();
    seedButton.textContent = revealText + ' Mnemonic';
    mnemonicRevealed = false;
    if (mnemonicTimeout) {
      clearTimeout(mnemonicTimeout);
      mnemonicTimeout = null;
    }
  }

  const xprvButton = document.createElement('button');
  xprvButton.id = 'emailXprvButton';
  xprvButton.className = 'copy-btn';
  xprvButton.textContent = revealText + ' XPRV';
  xprvButton.style.marginTop = '10px';
  xprvButton.style.display = 'block';

  let xprvRevealed = false;
  let xprvTimeout = null;

  xprvButton.addEventListener('click', async () => {
    armInactivityTimerSafely();
    
    if (!xprvRevealed) {
      if (!window.keyManager) {
        alert('KeyManager not available');
        return;
      }

      const xprv = await window.keyManager.retrieveKey('hd_xprv');
      if (!xprv) {
        alert('XPRV not available');
        return;
      }

      const xprvDisplay = document.createElement('div');
      xprvDisplay.id = 'tempXprvDisplay';
      xprvDisplay.style.cssText = `
        margin: 10px 0; 
        padding: 15px; 
        background: var(--glass-bg); 
        border: 1px solid var(--glass-border); 
        border-radius: 12px; 
        font-family: monospace; 
        word-break: break-all; 
        border-left: 4px solid #2196f3;
        position: relative;
      `;
      
      const xprvTitle = getTranslation('generate_section.xprv_title', 'XPRV HD Master Key:');
      const xprvWarning = getTranslation('generate_section.warning', 'Save the private key immediately!');
      const copyButtonText = getTranslation('generate_section.copy', 'Copy');
      const cancelText = getTranslation('send_section.cancel_button', 'Cancel');
      
      xprvDisplay.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 8px;">${xprvTitle}</div>
        <div class="blurred" id="xprvContent" style="background: rgba(0,0,0,0.05); padding: 8px; border-radius: 6px; margin-bottom: 8px; cursor: pointer;">${xprv}</div>
        <button id="revealXprvBtn" class="reveal-btn" style="margin-right: 8px;">${revealText}</button>
        <button id="copyXprvBtn" class="copy-btn" style="margin-right: 8px;">${copyButtonText}</button>
        <small style="color: var(--text-secondary); font-size: 0.85em;">
          ${xprvWarning}
        </small>
      `;

      container.appendChild(xprvDisplay);

      document.getElementById('revealXprvBtn').addEventListener('click', () => {
        armInactivityTimerSafely();
        const content = document.getElementById('xprvContent');
        if (content) content.classList.toggle('blurred');
      });

      document.getElementById('copyXprvBtn').addEventListener('click', async () => {
        armInactivityTimerSafely();
        try {
          await securityCopy(xprv, { isElementId: false });
          showCopyFeedback(true);
        } catch (error) {
          showCopyFeedback(false, error.message);
        }
      });

      xprvButton.textContent = cancelText;
      xprvRevealed = true;

      xprvTimeout = setTimeout(() => {
        hideXprv();
      }, 30000);

    } else {
      hideXprv();
    }
  });

  function hideXprv() {
    const xprvDisplay = document.getElementById('tempXprvDisplay');
    if (xprvDisplay) xprvDisplay.remove();
    xprvButton.textContent = revealText + ' XPRV';
    xprvRevealed = false;
    if (xprvTimeout) {
      clearTimeout(xprvTimeout);
      xprvTimeout = null;
    }
  }

  container.appendChild(seedButton);
  container.appendChild(xprvButton);
}

// === GENERATION HANDLERS ===
function setupGenerationHandlers() {
  addUniqueEventListener(ELEMENT_IDS.GENERATE_BUTTON, 'click', async () => {
    if (isButtonOnCooldown(ELEMENT_IDS.GENERATE_BUTTON, 5000)) return;
    
    armInactivityTimerSafely();
    
    if (window.isOperationActive && window.isOperationActive('generation')) {
      return;
    }
    
    if (window.keyManager && typeof window.keyManager.startGenerationTimer === 'function') {
      window.keyManager.startGenerationTimer();
    }
      
    try {
      if (window.startOperation) window.startOperation('generation');
      showBalanceLoadingSpinner(true, 'loading.wallet_setup');
      setButtonLoading(ELEMENT_IDS.GENERATE_BUTTON, true);
      
      armInactivityTimerSafely();

      const result = await window.generateHDWallet(24);
      const addresses = result.addresses;
        
      const hdKeyElement = document.getElementById(ELEMENT_IDS.HD_MASTER_KEY);
      const mnemonicElement = document.getElementById(ELEMENT_IDS.MNEMONIC_PHRASE);
      
      if (hdKeyElement) {
        hdKeyElement.textContent = '[Protected - Click Reveal]';
        hdKeyElement.classList.add('blurred');
      }
      
      if (mnemonicElement) {
        mnemonicElement.textContent = '[Protected - Click Reveal]';
        mnemonicElement.classList.add('blurred');
      }
      
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
    } catch (error) {
      const errorMsg = getTranslation('errors.generation_failed', `Generation error: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Generation error:', error);
    } finally {
      showBalanceLoadingSpinner(false);
      setButtonLoading(ELEMENT_IDS.GENERATE_BUTTON, false);
      if (window.endOperation) window.endOperation('generation');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.COPY_HD_KEY, 'click', async () => {
    armInactivityTimerSafely();
    
    if (!window.keyManager) {
      alert('KeyManager not available');
      return;
    }

    const xprv = await window.keyManager.retrieveKey('hd_xprv');
    if (!xprv) {
      alert('XPRV not available');
      return;
    }

    try {
      await securityCopy(xprv, { isElementId: false });
      showCopyFeedback(true);
    } catch (error) {
      showCopyFeedback(false, error.message);
    }
  });

  addUniqueEventListener(ELEMENT_IDS.COPY_MNEMONIC, 'click', async () => {
    armInactivityTimerSafely();
    
    if (!window.keyManager) {
      alert('KeyManager not available');
      return;
    }

    const mnemonic = await window.keyManager.retrieveKey('mnemonic');
    if (!mnemonic) {
      alert('Mnemonic not available');
      return;
    }

    try {
      await securityCopy(mnemonic, { isElementId: false });
      showCopyFeedback(true);
    } catch (error) {
      showCopyFeedback(false, error.message);
    }
  });

  let hdKeyTimeout = null;
  addUniqueEventListener('revealHdKey', 'click', async () => {
    armInactivityTimerSafely();
    
    const element = document.getElementById(ELEMENT_IDS.HD_MASTER_KEY);
    if (!element) return;

    if (element.classList.contains('blurred')) {
      if (!window.keyManager) {
        alert('KeyManager not available');
        return;
      }

      const xprv = await window.keyManager.retrieveKey('hd_xprv');
      if (!xprv) {
        alert('XPRV not available');
        return;
      }

      element.textContent = xprv;
      revealElement(ELEMENT_IDS.HD_MASTER_KEY);
      
      if (hdKeyTimeout) {
        clearTimeout(hdKeyTimeout);
      }
      
      hdKeyTimeout = setTimeout(() => {
        element.textContent = '[Protected - Click Reveal]';
        blurElement(ELEMENT_IDS.HD_MASTER_KEY);
        hdKeyTimeout = null;
      }, 30000);
    } else {
      if (hdKeyTimeout) {
        clearTimeout(hdKeyTimeout);
        hdKeyTimeout = null;
      }
      element.textContent = '[Protected - Click Reveal]';
      blurElement(ELEMENT_IDS.HD_MASTER_KEY);
    }
  });

  let mnemonicTimeout = null;
  addUniqueEventListener('revealMnemonic', 'click', async () => {
    armInactivityTimerSafely();
    
    const element = document.getElementById(ELEMENT_IDS.MNEMONIC_PHRASE);
    if (!element) return;

    if (element.classList.contains('blurred')) {
      if (!window.keyManager) {
        alert('KeyManager not available');
        return;
      }

      const mnemonic = await window.keyManager.retrieveKey('mnemonic');
      if (!mnemonic) {
        alert('Mnemonic not available');
        return;
      }

      element.textContent = mnemonic;
      revealElement(ELEMENT_IDS.MNEMONIC_PHRASE);
      
      if (mnemonicTimeout) {
        clearTimeout(mnemonicTimeout);
      }
      
      mnemonicTimeout = setTimeout(() => {
        element.textContent = '[Protected - Click Reveal]';
        blurElement(ELEMENT_IDS.MNEMONIC_PHRASE);
        mnemonicTimeout = null;
      }, 30000);
    } else {
      if (mnemonicTimeout) {
        clearTimeout(mnemonicTimeout);
        mnemonicTimeout = null;
      }
      element.textContent = '[Protected - Click Reveal]';
      blurElement(ELEMENT_IDS.MNEMONIC_PHRASE);
    }
  });
}

// === PASSWORD REVEAL TOGGLE ===
function setupPasswordRevealToggle() {
  const passwordInput = document.getElementById('passwordInput');
  const toggleBtn = document.getElementById('togglePasswordBtn');
  
  if (!passwordInput || !toggleBtn) return;
  
  let revealTimeout = null;
  let isRevealing = false;
  
  const hidePassword = () => {
    passwordInput.type = 'password';
    toggleBtn.textContent = '👁️';
    toggleBtn.classList.remove('revealing');
    isRevealing = false;
    
    if (revealTimeout) {
      clearTimeout(revealTimeout);
      revealTimeout = null;
    }
  };
  
  const showPassword = () => {
    passwordInput.type = 'text';
    toggleBtn.textContent = '🙈';
    toggleBtn.classList.add('revealing');
    isRevealing = true;
    
    revealTimeout = setTimeout(() => {
      hidePassword();
    }, 10000);
  };
  
  addUniqueEventListener('togglePasswordBtn', 'click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    armInactivityTimerSafely();
    
    if (isRevealing) {
      hidePassword();
    } else {
      showPassword();
    }
  });
  
  document.getElementById('tabKey')?.addEventListener('click', hidePassword);
}

// === IMPORT HANDLERS ===
function setupImportHandlers() {
  const emailForm = document.getElementById('emailInputs');
  if (emailForm) {
    emailForm.addEventListener('submit', (e) => {
      e.preventDefault();
      return false;
    });
  }

  addUniqueEventListener(ELEMENT_IDS.IMPORT_WALLET_BUTTON, 'click', async () => {
    if (isButtonOnCooldown(ELEMENT_IDS.IMPORT_WALLET_BUTTON, 10000)) return;
    
    armInactivityTimerSafely();
    
    if (window.isOperationActive && window.isOperationActive('import')) {
      return;
    }
    
    const input = document.getElementById(ELEMENT_IDS.PRIVATE_KEY_WIF)?.value?.trim();
    if (!input) {
      const errorMsg = getTranslation('errors.enter_key', 'Please enter a private key, mnemonic or XPRV');
      alert(errorMsg);
      return;
    }
      
    try {
      if (window.startOperation) window.startOperation('import');
      showBalanceLoadingSpinner(true, 'loading.importing_wallet');
      setButtonLoading(ELEMENT_IDS.IMPORT_WALLET_BUTTON, true);

      const result = await window.importWallet(input);
      
      if (result.success) {
        displayWalletInfo(result.addresses, result.importType, async () => {
          if (window.refreshAllBalances) {
            await window.refreshAllBalances();
          }
          showBalanceLoadingSpinner(false);
        });
        hideAllAuthForms();
        clearInputFields();
        
        console.log('[UI] Wallet imported successfully:', result.importType);
      } else {
        const errorMsg = getTranslation('errors.import_failed', `Import failed: ${result.error}`);
        alert(errorMsg);
        showBalanceLoadingSpinner(false);
      }
    } catch (error) {
      const errorMsg = getTranslation('errors.import_error', `Import error: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Import error:', error);
      showBalanceLoadingSpinner(false);
    } finally {
      setButtonLoading(ELEMENT_IDS.IMPORT_WALLET_BUTTON, false);
      if (window.endOperation) window.endOperation('import');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.CONNECT_EMAIL_BUTTON, 'click', async () => {
    if (isButtonOnCooldown(ELEMENT_IDS.CONNECT_EMAIL_BUTTON, 10000)) return;
    
    armInactivityTimerSafely();
    
    if (window.isOperationActive && window.isOperationActive('email-connect')) {
      return;
    }
    
    const email = document.getElementById(ELEMENT_IDS.EMAIL_INPUT)?.value?.trim();
    const password = document.getElementById(ELEMENT_IDS.PASSWORD_INPUT)?.value?.trim();
    
    if (!email || !password) {
      const errorMsg = getTranslation('errors.enter_email_password', 'Please enter email and password');
      alert(errorMsg);
      return;
    }
      
    try {
      if (window.startOperation) window.startOperation('email-connect');
      showBalanceLoadingSpinner(true, 'loading.connecting_email');
      setButtonLoading(ELEMENT_IDS.CONNECT_EMAIL_BUTTON, true);
      
      const result = await window.importWallet(email, password);
      
      if (result.success) {
        displayWalletInfo(result.addresses, result.importType, async () => {
          if (window.refreshAllBalances) {
            await window.refreshAllBalances();
          }
          showBalanceLoadingSpinner(false);
        });
        hideAllAuthForms();
        clearInputFields();

        setTimeout(() => {
          createSecureCredentialsButtons(null, null, 'credentialsButtonsContainer');
        }, 100);
        
      } else {
        const errorMsg = getTranslation('errors.connection_failed', `Connection failed: ${result.error}`);
        alert(errorMsg);
        showBalanceLoadingSpinner(false);
      }
    } catch (error) {
      const errorMsg = getTranslation('errors.connection_error', `Connection error: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Connection error:', error);
      showBalanceLoadingSpinner(false);
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
  addUniqueEventListener(ELEMENT_IDS.MAX_BUTTON, 'click', async () => {
    armInactivityTimerSafely();
    
    const maxButton = document.getElementById(ELEMENT_IDS.MAX_BUTTON);
    const amtEl = document.getElementById(ELEMENT_IDS.AMOUNT_NITO);
    
    if (maxButton) {
      maxButton.disabled = true;
      const calculatingText = getTranslation('ui.calculating', 'Calculating...');
      maxButton.textContent = calculatingText;
    }
    
    try {
      if (!window.isWalletReady || !window.isWalletReady()) {
        const errorMsg = getTranslation('errors.import_first', 'Import a wallet first.');
        alert(errorMsg);
        return;
      }

      if (!window.calculateMaxSendableAmount) {
        const msg = getTranslation('ui.max_function_unavailable', 'calculateMaxSendableAmount function unavailable');
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
      
      const errorMsg = getTranslation('ui.max_calculation_error', `MAX calculation error: ${error.message}`);
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
    if (isButtonOnCooldown(ELEMENT_IDS.PREPARE_TX_BUTTON, 5000)) return;
    
    armInactivityTimerSafely();
    
    if (window.isOperationActive && window.isOperationActive('transaction')) {
      return;
    }
    
    try {
      if (window.startOperation) window.startOperation('transaction');
      showBalanceLoadingSpinner(true, 'loading.preparing_transaction');
      setButtonLoading(ELEMENT_IDS.PREPARE_TX_BUTTON, true);
      
      const to = document.getElementById(ELEMENT_IDS.DESTINATION_ADDRESS)?.value?.trim();
      const amount = parseFloat(document.getElementById(ELEMENT_IDS.AMOUNT_NITO)?.value || '0');
      
      if (!to) {
        const msg = getTranslation('ui.enter_destination_address', 'Please enter a destination address');
        throw new Error(msg);
      }
      
      if (!amount || amount <= 0) {
        const msg = getTranslation('ui.invalid_amount', 'Invalid amount');
        throw new Error(msg);
      }
      
      if (!window.signTxWithPSBT) {
        const msg = getTranslation('errors.transaction_functions_unavailable', 'Transaction functions unavailable');
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
      const errorMsg = getTranslation('errors.transaction_prep_failed', `Transaction preparation failed: ${error.message}`);
      alert(errorMsg);
      console.error('[TX-PREP] Transaction preparation error:', error);
      isMaxButtonUsed = false;
    } finally {
      showBalanceLoadingSpinner(false);
      setButtonLoading(ELEMENT_IDS.PREPARE_TX_BUTTON, false);
      if (window.endOperation) window.endOperation('transaction');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.BROADCAST_TX_BUTTON, 'click', async () => {
    if (isButtonOnCooldown(ELEMENT_IDS.BROADCAST_TX_BUTTON, 10000)) return;
    
    armInactivityTimerSafely();
    
    if (window.isOperationActive && window.isOperationActive('broadcast')) {
      return;
    }
    
    try {
      if (window.startOperation) window.startOperation('broadcast');
      showBalanceLoadingSpinner(true, 'loading.broadcasting');
      setButtonLoading(ELEMENT_IDS.BROADCAST_TX_BUTTON, true);
      
      const hex = document.getElementById(ELEMENT_IDS.SIGNED_TX)?.textContent;
      if (!hex) {
        const errorMsg = getTranslation('errors.no_transaction', 'No transaction to broadcast');
        alert(errorMsg);
        return;
      }
      
      if (!window.rpc) {
        const errorMsg = getTranslation('errors.rpc_unavailable', 'RPC function unavailable');
        throw new Error(errorMsg);
      }
      
      const txid = await window.rpc('sendrawtransaction', [hex]);
      
      await showSuccessPopup(txid);
      
      document.getElementById(ELEMENT_IDS.DESTINATION_ADDRESS).value = '';
      document.getElementById(ELEMENT_IDS.AMOUNT_NITO).value = '';
      document.getElementById(ELEMENT_IDS.TX_HEX_CONTAINER).style.display = 'none';
      document.getElementById(ELEMENT_IDS.BROADCAST_TX_BUTTON).style.display = 'none';
      document.getElementById(ELEMENT_IDS.CANCEL_TX_BUTTON).style.display = 'none';
      
    } catch (error) {
      const errorMsg = getTranslation('errors.broadcast_failed', `Broadcast failed: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Broadcast error:', error);
    } finally {
      showBalanceLoadingSpinner(false);
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

// === MESSAGING INTERFACE ===
export function setupMessagingInterface() {
  setupMessagingButtons();
  
  const messageInput = document.getElementById(ELEMENT_IDS.MESSAGE_INPUT);
  if (messageInput) {
    const existingListener = handlerRegistry.get(`${ELEMENT_IDS.MESSAGE_INPUT}:input`);
    if (!existingListener) {
      messageInput.addEventListener('input', updateCharCounter);
      handlerRegistry.set(`${ELEMENT_IDS.MESSAGE_INPUT}:input`, updateCharCounter);
    }
    updateCharCounter();
  }
}

export function setupMessagingButtons() {
  addUniqueEventListener(ELEMENT_IDS.PUBLISH_PUBKEY_BUTTON, 'click', async () => {
    if (isButtonOnCooldown(ELEMENT_IDS.PUBLISH_PUBKEY_BUTTON, 5000)) return;
    
    armInactivityTimerSafely();
    
    try {
      if (!window.messaging) {
        if (window.initializeMessaging) {
          window.messaging = await window.initializeMessaging();
        } else {
          const errorMsg = getTranslation('errors.consolidation_unavailable', 'Consolidation function unavailable');
          alert(errorMsg);
          return;
        }
      }
      
      await window.messaging.publishPublicKey();
    } catch (error) {
      console.error('[UI] Publish error:', error);
      const errorMsg = getTranslation('errors.error_details', 'Error');
      alert(`${errorMsg}: ${error.message}`);
    }
  });
  
  addUniqueEventListener(ELEMENT_IDS.SEND_MESSAGE_BUTTON, 'click', async () => {
    if (isButtonOnCooldown(ELEMENT_IDS.SEND_MESSAGE_BUTTON, 10000)) return;
    
    armInactivityTimerSafely();
    
    try {
      if (!window.messaging) {
        if (window.initializeMessaging) {
          window.messaging = await window.initializeMessaging();
        } else {
          const errorMsg = getTranslation('errors.consolidation_unavailable', 'Consolidation function unavailable');
          alert(errorMsg);
          return;
        }
      }
      
      await window.messaging.sendMessage();
    } catch (error) {
      console.error('[UI] Send error:', error);
      const errorMsg = getTranslation('errors.error_details', 'Error');
      alert(`${errorMsg}: ${error.message}`);
    }
  });
  
  addUniqueEventListener(ELEMENT_IDS.CLEAR_MESSAGE_BUTTON, 'click', () => {
    armInactivityTimerSafely();
    
    const messageInput = document.getElementById(ELEMENT_IDS.MESSAGE_INPUT);
    if (messageInput) {
      messageInput.value = '';
      updateCharCounter();
    }
  });
  
  addUniqueEventListener(ELEMENT_IDS.REFRESH_MESSAGES_BUTTON, 'click', async () => {
    if (isButtonOnCooldown(ELEMENT_IDS.REFRESH_MESSAGES_BUTTON, 5000)) return;
    
    armInactivityTimerSafely();
    
    try {
      if (!window.messaging) {
        if (window.initializeMessaging) {
          window.messaging = await window.initializeMessaging();
        } else {
          const errorMsg = getTranslation('errors.consolidation_unavailable', 'Consolidation function unavailable');
          alert(errorMsg);
          return;
        }
      }
      
      await window.messaging.scanInboxMessages();
    } catch (error) {
      console.error('[UI] Refresh error:', error);
      const errorMsg = getTranslation('errors.error_details', 'Error');
      alert(`${errorMsg}: ${error.message}`);
    }
  });
}

export function updateCharCounter() {
  const messageInput = document.getElementById(ELEMENT_IDS.MESSAGE_INPUT);
  const charCounter = document.getElementById(ELEMENT_IDS.MESSAGE_CHAR_COUNTER);
  
  if (messageInput && charCounter) {
    const currentLength = messageInput.value.length;
    const maxLength = 50000;
    charCounter.textContent = `${currentLength}/${maxLength}`;
    
    if (currentLength > maxLength * 0.9) {
      charCounter.style.color = '#ef4444';
    } else if (currentLength > maxLength * 0.75) {
      charCounter.style.color = '#f59e0b';
    } else {
      charCounter.style.color = '';
    }
  }
}

// === MESSAGE DISPLAY ===
export function displayMessages(messages) {
  const messageList = document.getElementById(ELEMENT_IDS.MESSAGE_LIST);
  if (!messageList) return;
  
  if (!messages || messages.length === 0) {
    const noMsgText = getTranslation('messaging.no_messages_received', 'No messages received');
    messageList.innerHTML = `<p style="text-align: center; opacity: 0.6;">${noMsgText}</p>`;
    return;
  }
  
  const items = messages.map(msg => ({
    id: msg.id,
    from: msg.from,
    body: msg.body,
    timestamp: msg.timestamp,
    read: msg.read || false
  }));
  
  messageList.innerHTML = renderInboxEmailStyle(items);
  
  messageList.querySelectorAll('[data-message-id]').forEach(el => {
    el.addEventListener('click', () => {
      const msgId = el.getAttribute('data-message-id');
      const message = messages.find(m => m.id === msgId);
      if (message && window.showMessageModal) {
        window.showMessageModal(message.id, message.from, message.body);
      }
    });
  });
}

export function renderInboxEmailStyle(items) {
  if (!items || items.length === 0) {
    const noMsgText = getTranslation('messaging.no_messages_received', 'No messages received');
    return `<p style="text-align: center; opacity: 0.6;">${noMsgText}</p>`;
  }
  
  const isDarkMode = document.body.getAttribute('data-theme') === 'dark';
  
  return items.map(item => {
    const preview = item.body.substring(0, 80) + (item.body.length > 80 ? '...' : '');
    const unreadStyle = item.read ? '' : 'font-weight: 700;';
    
    return `
      <div data-message-id="${item.id}" style="
        padding: 1rem;
        border-bottom: 1px solid ${isDarkMode ? '#374151' : '#e5e7eb'};
        cursor: pointer;
        transition: background 0.2s;
        ${unreadStyle}
      " onmouseover="this.style.background='${isDarkMode ? '#1f2937' : '#f9fafb'}'" 
         onmouseout="this.style.background='transparent'">
        <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
          <div style="color: ${isDarkMode ? '#60a5fa' : '#2563eb'}; font-size: 0.875rem;">
            ${item.from.substring(0, 20)}...
          </div>
          <div style="color: ${isDarkMode ? '#9ca3af' : '#6b7280'}; font-size: 0.75rem;">
            ${new Date(item.timestamp).toLocaleString()}
          </div>
        </div>
        <div style="color: ${isDarkMode ? '#d1d5db' : '#374151'}; font-size: 0.875rem;">
          ${preview}
        </div>
      </div>
    `;
  }).join('');
}

export function updateUnreadCounter(count) {
  const unreadCount = document.getElementById(ELEMENT_IDS.UNREAD_COUNT);
  if (unreadCount) {
    unreadCount.textContent = count > 0 ? count : '';
    unreadCount.style.display = count > 0 ? 'inline-block' : 'none';
  }
}

// === SETUP AND CLEANUP ===
export function setupUIHandlers() {
  if (setupComplete) {
    return true;
  }
  
  try {
    setupGenerationHandlers();
    setupImportHandlers();
    setupPasswordRevealToggle();
    setupAuthenticationSystem();
    setupTransactionHandlers();
    
    setTimeout(() => {
      setupMessagingInterface();
    }, 100);
    
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
  buttonCooldowns.clear();
  setupComplete = false;
}

// === INITIALIZATION ===
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
        setupMessagingInterface();
      }, 250);
      
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

// === GLOBAL EXPORTS ===
if (typeof window !== 'undefined') {
  window.setupUIHandlers = setupUIHandlers;
  window.cleanupUIHandlers = cleanupUIHandlers;
  window.addUniqueEventListener = addUniqueEventListener;
  window.removeEventListener = removeEventListener;
  window.displayWalletInfo = displayWalletInfo;
  window.updateAddressSelector = updateAddressSelector;
  window.hideAllAuthForms = hideAllAuthForms;
  window.clearInputFields = clearInputFields;
  window.createSecureCredentialsButtons = createSecureCredentialsButtons;
  window.copyToClipboard = copyToClipboard;
  window.setButtonLoading = setButtonLoading;
  window.setupMessagingInterface = setupMessagingInterface;
  window.setupMessagingButtons = setupMessagingButtons;
  window.updateCharCounter = updateCharCounter;
  window.displayMessages = displayMessages;
  window.renderInboxEmailStyle = renderInboxEmailStyle;
  window.updateUnreadCounter = updateUnreadCounter;
}