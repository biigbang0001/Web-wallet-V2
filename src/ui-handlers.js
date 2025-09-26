// UI Event Handlers for NITO Wallet

import { ELEMENT_IDS, FEATURE_FLAGS } from './config.js';
import { copyToClipboard, armInactivityTimerSafely } from './security.js';
import { eventBus, EVENTS } from './events.js';

// === TRANSLATION HELPER ===
function getTranslation(key, fallback, params = {}) {
  const t = (window.i18next && typeof window.i18next.t === 'function') 
    ? window.i18next.t 
    : () => fallback || key;
  return t(key, { ...params, defaultValue: fallback });
}

// === EVENT HANDLER DEDUPLICATION ===
const handlerRegistry = new Map();
let setupComplete = false;

function addUniqueEventListener(elementId, eventType, handler, options = {}) {
  const element = document.getElementById(elementId);
  if (!element) {
    console.warn(`[UI] Element not found: ${elementId}`);
    return false;
  }

  const key = `${elementId}:${eventType}`;
  
  // Remove existing handler if present
  if (handlerRegistry.has(key)) {
    const oldHandler = handlerRegistry.get(key);
    element.removeEventListener(eventType, oldHandler);
    handlerRegistry.delete(key);
  }

  // Add new handler
  element.addEventListener(eventType, handler, options);
  handlerRegistry.set(key, handler);
  
  console.log(`[UI] Handler registered: ${key}`);
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

// === OPERATION TRACKING ===
function isOperationActive(operationType = null) {
  if (window.isOperationActive) {
    return window.isOperationActive(operationType);
  }
  return false;
}

function startOperation(operationType) {
  if (window.startOperation) {
    window.startOperation(operationType);
  }
}

function endOperation(operationType) {
  if (window.endOperation) {
    window.endOperation(operationType);
  }
}

// === LOADING SYSTEM WITH i18n ===
function showLoadingSpinner(show) {
  const spinner = document.getElementById(ELEMENT_IDS.LOADING_SPINNER);
  if (spinner) {
    spinner.style.display = show ? 'block' : 'none';
  }
}

function showConnectionLoadingSpinner(show, messageKey = 'loading.connecting') {
  let modal = document.getElementById('connectionLoadingModal');
  
  if (show) {
    if (isOperationActive('connection')) {
      console.log('[UI] Connection already in progress');
      return;
    }
    startOperation('connection');
    
    const t = (window.i18next && typeof window.i18next.t === 'function') 
      ? window.i18next.t 
      : (key, fallback) => fallback || key;
      
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'connectionLoadingModal';
      modal.style.cssText = `
        display: flex;
        position: fixed;
        inset: 0;
        background: rgba(0,0,0,.4);
        backdrop-filter: blur(6px);
        z-index: 10000;
        align-items: center;
        justify-content: center;
      `;
      
      document.body.appendChild(modal);
    }
    
    const isDarkMode = document.body.getAttribute('data-theme') === 'dark';
    const message = t(messageKey, 'Connexion en cours...');
    const subtitle = t('loading.wallet_setup', 'Configuration du portefeuille...');
    
    modal.innerHTML = `
      <div style="
        background: ${isDarkMode ? '#1a202c' : '#ffffff'};
        color: ${isDarkMode ? '#e2e8f0' : '#111111'};
        border: 1px solid ${isDarkMode ? '#4a5568' : '#e2e8f0'};
        padding: 2rem 2.5rem;
        border-radius: 20px;
        box-shadow: 0 15px 40px rgba(0,0,0,${isDarkMode ? '0.6' : '0.25'});
        text-align: center;
        min-width: 320px;
        max-width: 90vw;
        backdrop-filter: blur(15px);
        border: 2px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'};
      ">
        <div style="font-size:3rem; line-height:1; margin-bottom:1.2rem; animation: rotate 1.5s linear infinite;">🔐</div>
        <div class="loading-text" style="font-weight:700; font-size: 20px; margin-bottom: 0.8rem; color: ${isDarkMode ? '#60a5fa' : '#2563eb'};">${message}</div>
        <div style="font-size: 15px; opacity: 0.8; margin-bottom: 1rem;">${subtitle}</div>
        <div style="width: 100%; background: ${isDarkMode ? '#374151' : '#e5e7eb'}; border-radius: 10px; height: 6px; overflow: hidden;">
          <div style="width: 100%; height: 100%; background: linear-gradient(90deg, ${isDarkMode ? '#3b82f6' : '#2563eb'}, ${isDarkMode ? '#1e40af' : '#1d4ed8'}); border-radius: 10px; animation: loading-bar 2s ease-in-out infinite;"></div>
        </div>
      </div>
    `;
    
    // Ajouter l'animation CSS si elle n'existe pas
    if (!document.querySelector('#loading-bar-style')) {
      const style = document.createElement('style');
      style.id = 'loading-bar-style';
      style.textContent = `
        @keyframes loading-bar {
          0%, 100% { transform: translateX(-100%); }
          50% { transform: translateX(100%); }
        }
        @keyframes rotate {
          100% { transform: rotate(360deg); }
        }
      `;
      document.head.appendChild(style);
    }
    
    modal.style.display = 'flex';
  } else {
    if (modal) {
      modal.style.display = 'none';
    }
    endOperation('connection');
  }
}

function setButtonLoading(buttonId, loading, originalText = null) {
  const button = document.getElementById(buttonId);
  if (!button) return;
  
  const t = (window.i18next && typeof window.i18next.t === 'function') 
    ? window.i18next.t 
    : (key, fallback) => fallback || key;
  
  if (loading) {
    if (!button.dataset.originalText) {
      button.dataset.originalText = button.textContent;
    }
    button.innerHTML = t('loading.refreshing', '⌛ Actualisation...');
    button.disabled = true;
    button.style.opacity = '0.7';
  } else {
    const text = originalText || button.dataset.originalText;
    if (text) {
      button.textContent = text;
    } else {
      // Fallback avec i18n
      const refreshText = t('import_section.refresh_button', '🔄 Actualiser');
      button.textContent = refreshText;
    }
    button.disabled = false;
    button.style.opacity = '1';
    delete button.dataset.originalText;
  }
}

async function updateBalance() {
  try {
    if (window.getTotalBalance) {
      const total = await window.getTotalBalance();
      const balanceElement = document.getElementById('totalBalance');
      if (balanceElement) {
        balanceElement.textContent = total.toFixed(8) + ' NITO';
      }
    }
  } catch (error) {
    console.error('[UI] Balance update error:', error);
  }
}

async function updateBalanceWithLoading() {
  if (isOperationActive('balance-update')) {
    console.log('[UI] Balance update already in progress');
    return;
  }
  
  startOperation('balance-update');
  
  if (window.showBalanceLoadingSpinner) {
    window.showBalanceLoadingSpinner(true, 'loading.balance_refresh');
  }
  
  try {
    // Nettoyer les caches blockchain pour forcer une vraie mise à jour
    if (window.clearBlockchainCaches) {
      const maybePromise = window.clearBlockchainCaches();
      if (maybePromise && typeof maybePromise.then === 'function') {
        await maybePromise;
      }
    }
    
    // Attendre un peu pour que le nettoyage prenne effet
    await new Promise(r => setTimeout(r, 500));
    
    // Mise à jour des soldes - ÉVITER LE DOUBLE REFRESH
    if (typeof window.updateSendTabBalance === 'function' && !isOperationActive('balance-refresh')) {
      await window.updateSendTabBalance();
    }
    
    await updateBalance();
    
    // Animation de succès
    if (window.showBalanceLoadingSpinner) {
      window.showBalanceLoadingSpinner(true, 'loading.balance_updated');
      await new Promise(r => setTimeout(r, 1000));
    }
    
  } catch (error) {
    console.error('[UI] Balance update error:', error);
    if (window.showBalanceLoadingSpinner) {
      window.showBalanceLoadingSpinner(true, 'loading.update_error');
      await new Promise(r => setTimeout(r, 1500));
    }
  } finally {
    if (window.showBalanceLoadingSpinner) {
      window.showBalanceLoadingSpinner(false);
    }
    endOperation('balance-update');
  }
}

async function showSuccessPopup(txid) {
  if (window.showSuccessPopup) {
    await window.showSuccessPopup(txid);
  } else {
    const successMsg = getTranslation('popup.transaction_success', 
      `Transaction réussie ! TXID: ${txid}`, 
      { txid }
    );
    alert(successMsg);
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

function displayWalletInfo(addresses, importType) {
  const walletAddressElement = document.getElementById(ELEMENT_IDS.WALLET_ADDRESS);
  const bech32Element = document.getElementById(ELEMENT_IDS.BECH32_ADDRESS);
  const taprootElement = document.getElementById(ELEMENT_IDS.TAPROOT_ADDRESS);
  const addressesSection = document.getElementById('nito-addresses');
  
  if (walletAddressElement && addresses) {
    const balanceText = getTranslation('import_section.balance', 'Solde:');
    
    walletAddressElement.innerHTML = `
      <div style="margin-top: 10px;">
        <strong>Bech32:</strong> ${addresses.bech32}<br>
        <strong>Taproot:</strong> ${addresses.taproot}
      </div>
      <div id="totalBalance" style="margin-top: 10px; font-weight: bold; color: #2196F3;">
        ${balanceText} 0.00000000 NITO
      </div>
    `;
    
    if (addressesSection) {
      addressesSection.style.display = 'block';
      if (bech32Element) bech32Element.value = addresses.bech32 || '';
      if (taprootElement) taprootElement.value = addresses.taproot || '';
    }
  }
  
  // Log des adresses comme demandé
  if (FEATURE_FLAGS.LOG_ADDRESSES) {
    console.log('=== WALLET ADDRESSES ===');
    console.log('Bech32:', addresses.bech32);
    console.log('Bech32m (Taproot):', addresses.taproot);
    console.log('Legacy:', addresses.legacy);
    console.log('P2SH:', addresses.p2sh);
    console.log('========================');
  }
  
  // Mise à jour du solde avec animation de chargement
  setTimeout(() => {
    updateBalanceWithLoading();
  }, 1000);
  
  injectConsolidateButton();
}

function injectConsolidateButton() {
  const consolidateContainer = document.querySelector('.consolidate-container');
  if (consolidateContainer && !consolidateContainer.querySelector('#consolidateButton')) {
    const t = (window.i18next && typeof window.i18next.t === 'function') 
      ? window.i18next.t 
      : (key, fallback) => fallback || key;
      
    const consolidateButton = document.createElement('button');
    consolidateButton.id = 'consolidateButton';
    consolidateButton.className = 'consolidate-button';
    consolidateButton.type = 'button';
    consolidateButton.setAttribute('data-i18n','consolidate.cta'); 
    consolidateButton.textContent = t('consolidate.cta', 'Consolider les UTXOs');
    consolidateButton.style.display = 'inline-block';
    consolidateButton.style.marginTop = '10px';
    
    consolidateButton.addEventListener('click', async () => {
      if (isOperationActive('consolidation')) {
        console.log('[UI] Consolidation already in progress');
        return;
      }
      
      if (window.consolidateUtxos) {
        await window.consolidateUtxos();
        setTimeout(() => updateBalanceWithLoading(), 3000);
      } else {
        const errorMsg = getTranslation('errors.consolidation_unavailable', 'Fonction de consolidation non disponible');
        alert(errorMsg);
      }
    });
    
    consolidateContainer.appendChild(consolidateButton);
  }
}

// === SECURE SEED COPY SYSTEM WITH i18n ===
function createSecureSeedButton(mnemonic, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const t = (window.i18next && typeof window.i18next.t === 'function') 
    ? window.i18next.t 
    : (key, fallback) => fallback || key;

  // Remove existing seed button if any
  const existingSeedButton = document.getElementById(ELEMENT_IDS.EMAIL_SEED_BUTTON);
  if (existingSeedButton) {
    existingSeedButton.remove();
  }

  const seedButton = document.createElement('button');
  seedButton.id = ELEMENT_IDS.EMAIL_SEED_BUTTON;
  seedButton.className = 'reveal-btn';
  seedButton.textContent = t('seed_reveal.button_reveal', '🔒 Révéler la phrase mnémotechnique');
  seedButton.style.marginTop = '10px';
  seedButton.style.display = 'block';

  let isRevealed = false;
  let revealTimeout = null;

  seedButton.addEventListener('click', () => {
    if (!isRevealed) {
      // Révéler la seed
      armInactivityTimerSafely();
      
      // Créer un élément temporaire pour afficher la seed
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
      
      const warningText = t('seed_reveal.warning_title', '⚠️ Phrase mnémotechnique (24 mots) :');
      const copyButtonText = t('seed_reveal.copy_button', '📋 Copier');
      const timeoutWarning = t('seed_reveal.timeout_warning', 'Cette phrase sera automatiquement masquée dans 30 secondes');
      
      seedDisplay.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 8px;">${warningText}</div>
        <div style="background: rgba(0,0,0,0.05); padding: 8px; border-radius: 6px; margin-bottom: 8px;">${mnemonic}</div>
        <button id="copySeedBtn" class="copy-btn" style="margin-right: 8px;">${copyButtonText}</button>
        <small style="color: var(--text-secondary); font-size: 0.85em;">
          ${timeoutWarning}
        </small>
      `;

      container.appendChild(seedDisplay);

      // Bouton de copie
      document.getElementById('copySeedBtn').addEventListener('click', () => {
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(mnemonic).then(() => {
            const successMsg = t('seed_reveal.copy_success', 'Phrase mnémotechnique copiée dans le presse-papiers !');
            alert(successMsg);
          }).catch(() => {
            // Fallback
            const textArea = document.createElement('textarea');
            textArea.value = mnemonic;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            const fallbackMsg = t('seed_reveal.copy_fallback', 'Phrase mnémotechnique copiée !');
            alert(fallbackMsg);
          });
        }
      });

      // Changer le bouton principal
      seedButton.textContent = t('seed_reveal.button_hide', '🔒 Masquer la phrase');
      isRevealed = true;

      // Auto-masquer après 30 secondes
      revealTimeout = setTimeout(() => {
        hideSeed();
      }, 30000);

    } else {
      // Masquer la seed
      hideSeed();
    }
  });

  function hideSeed() {
    const seedDisplay = document.getElementById('tempSeedDisplay');
    if (seedDisplay) {
      seedDisplay.remove();
    }
    seedButton.textContent = t('seed_reveal.button_reveal', '🔒 Révéler la phrase mnémotechnique');
    isRevealed = false;
    
    if (revealTimeout) {
      clearTimeout(revealTimeout);
      revealTimeout = null;
    }
  }

  container.appendChild(seedButton);
  return seedButton;
}

// === WALLET GENERATION HANDLERS ===
function setupGenerationHandlers() {
  console.log('[UI] Setting up generation handlers...');
  
  addUniqueEventListener(ELEMENT_IDS.GENERATE_BUTTON, 'click', async () => {
    if (isOperationActive('generation')) {
      console.log('[UI] Generation already in progress');
      return;
    }
    
    const t = (window.i18next && typeof window.i18next.t === 'function') 
      ? window.i18next.t 
      : (key, fallback) => fallback || key;
      
    try {
      startOperation('generation');
      showLoadingSpinner(true);
      setButtonLoading(ELEMENT_IDS.GENERATE_BUTTON, true);
      
      // ⚠️ IMPORTANT: Démarrer le timer d'inactivité seulement lors de la génération
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

        const logMessage = getTranslation('wallet.hd_wallet_generated', 
          'Portefeuille HD généré (24 mots):', 
          { words: 24 }
        );
        console.log(logMessage, {
          bech32: addresses.bech32,
          taproot: addresses.taproot,
          legacy: addresses.legacy,
          p2sh: addresses.p2sh
        });
      }
    } catch (error) {
      const errorMsg = getTranslation('errors.generation_failed', `Erreur de génération: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Generation error:', error);
    } finally {
      showLoadingSpinner(false);
      setButtonLoading(ELEMENT_IDS.GENERATE_BUTTON, false);
      endOperation('generation');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.COPY_HD_KEY, 'click', () => {
    copyToClipboard(ELEMENT_IDS.HD_MASTER_KEY);
  });

  addUniqueEventListener(ELEMENT_IDS.COPY_MNEMONIC, 'click', () => {
    copyToClipboard(ELEMENT_IDS.MNEMONIC_PHRASE);
  });
  
  console.log('[UI] Generation handlers setup completed');
}

// === WALLET IMPORT HANDLERS ===
function setupImportHandlers() {
  console.log('[UI] Setting up import handlers...');
  
  addUniqueEventListener(ELEMENT_IDS.IMPORT_WALLET_BUTTON, 'click', async () => {
    if (isOperationActive('import')) {
      console.log('[UI] Import already in progress');
      return;
    }
    
    const t = (window.i18next && typeof window.i18next.t === 'function') 
      ? window.i18next.t 
      : (key, fallback) => fallback || key;
      
    try {
      startOperation('import');
      showConnectionLoadingSpinner(true, 'loading.importing_wallet');
      setButtonLoading(ELEMENT_IDS.IMPORT_WALLET_BUTTON, true);
      
      const input = document.getElementById(ELEMENT_IDS.PRIVATE_KEY_WIF)?.value?.trim();
      if (!input) {
        const errorMsg = getTranslation('errors.enter_key', 'Veuillez entrer une clé privée, mnemonic ou XPRV');
        alert(errorMsg);
        return;
      }

      const result = await window.importWallet(input);
      
      if (result.success) {
        const logMessage = getTranslation('wallet.import_successful_calculating', 'Import réussi, calcul des soldes...');
        console.log(logMessage);
        displayWalletInfo(result.addresses, result.importType);
        hideAllAuthForms();
        clearInputFields();
        
        const successMessage = getTranslation('wallet.wallet_imported_successfully', 'Portefeuille importé avec succès:');
        console.log(successMessage, result.importType);
      } else {
        const errorMsg = getTranslation('errors.import_failed', `Échec de l'import: ${result.error}`);
        alert(errorMsg);
      }
    } catch (error) {
      const errorMsg = getTranslation('errors.import_error', `Erreur d'import: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Import error:', error);
    } finally {
      showConnectionLoadingSpinner(false);
      setButtonLoading(ELEMENT_IDS.IMPORT_WALLET_BUTTON, false);
      endOperation('import');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.CONNECT_EMAIL_BUTTON, 'click', async () => {
    if (isOperationActive('email-connect')) {
      console.log('[UI] Email connection already in progress');
      return;
    }
    
    const t = (window.i18next && typeof window.i18next.t === 'function') 
      ? window.i18next.t 
      : (key, fallback) => fallback || key;
      
    try {
      startOperation('email-connect');
      showConnectionLoadingSpinner(true, 'loading.connecting_email');
      setButtonLoading(ELEMENT_IDS.CONNECT_EMAIL_BUTTON, true);
      
      const email = document.getElementById(ELEMENT_IDS.EMAIL_INPUT)?.value?.trim();
      const password = document.getElementById(ELEMENT_IDS.PASSWORD_INPUT)?.value?.trim();
      
      if (!email || !password) {
        const errorMsg = getTranslation('errors.enter_email_password', 'Veuillez entrer l\'email et le mot de passe');
        alert(errorMsg);
        return;
      }

      const connectionMessage = getTranslation('wallet.email_connection_started', 'Connexion email démarrée, génération du portefeuille...');
      console.log(connectionMessage);
      
      const result = await window.importWallet(email, password);
      
      if (result.success) {
        const walletMessage = getTranslation('wallet.email_wallet_generated', 'Portefeuille email généré, calcul des soldes...');
        console.log(walletMessage);
        displayWalletInfo(result.addresses, result.importType);
        hideAllAuthForms();
        clearInputFields();

        // Créer le bouton sécurisé de copie de seed
        if (result.mnemonic) {
          createSecureSeedButton(result.mnemonic, 'emailForm');
        }
        
        const successMessage = getTranslation('wallet.email_wallet_connected', 
          'Portefeuille email connecté avec succès (24 mots)',
          { words: 24 }
        );
        console.log(successMessage);
      } else {
        const errorMsg = getTranslation('errors.connection_failed', `Échec de la connexion: ${result.error}`);
        alert(errorMsg);
      }
    } catch (error) {
      const errorMsg = getTranslation('errors.connection_error', `Erreur de connexion: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Connection error:', error);
    } finally {
      showConnectionLoadingSpinner(false);
      setButtonLoading(ELEMENT_IDS.CONNECT_EMAIL_BUTTON, false);
      endOperation('email-connect');
    }
  });

  // Boutons de rafraîchissement standardisés avec déduplication
  addUniqueEventListener(ELEMENT_IDS.REFRESH_BALANCE_BUTTON, 'click', async () => {
    try {
      setButtonLoading(ELEMENT_IDS.REFRESH_BALANCE_BUTTON, true);
      await updateBalanceWithLoading();
    } catch (error) {
      console.error('[UI] Refresh balance error:', error);
    } finally {
      setButtonLoading(ELEMENT_IDS.REFRESH_BALANCE_BUTTON, false);
    }
  });
  
  console.log('[UI] Import handlers setup completed');
}

// === AUTHENTICATION SYSTEM ===
function setupAuthenticationSystem() {
  console.log('[UI] Setting up authentication system...');
  
  const tabEmail = document.getElementById('tabEmail');
  const tabKey = document.getElementById('tabKey');
  const emailForm = document.getElementById('emailForm');
  const keyForm = document.getElementById('keyForm');

  if (tabEmail && tabKey && emailForm && keyForm) {
    addUniqueEventListener('tabEmail', 'click', () => {
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
  
  console.log('[UI] Authentication system setup completed');
}

// === ENHANCED TRANSACTION HANDLERS ===
function setupTransactionHandlers() {
  console.log('[UI] Setting up transaction handlers...');
  
  const t = (window.i18next && typeof window.i18next.t === 'function') 
    ? window.i18next.t 
    : (key, fallback) => fallback || key;
    
  addUniqueEventListener(ELEMENT_IDS.MAX_BUTTON, 'click', async () => {
    try {
      if (!window.isWalletReady || !window.isWalletReady()) {
        const errorMsg = getTranslation('errors.import_first', 'Importez d\'abord un wallet');
        alert(errorMsg);
        return;
      }
      
      if (window.getTotalBalance) {
        const totalBal = await window.getTotalBalance();
        const maxAmount = Math.max(0, totalBal - 0.0001);
        document.getElementById(ELEMENT_IDS.AMOUNT_NITO).value = maxAmount.toFixed(8);
      }
    } catch (error) {
      console.error('[UI] MAX button error:', error);
    }
  });

  addUniqueEventListener(ELEMENT_IDS.PREPARE_TX_BUTTON, 'click', async () => {
    if (isOperationActive('transaction')) {
      console.log('[UI] Transaction already in progress');
      return;
    }
    
    try {
      startOperation('transaction');
      showLoadingSpinner(true);
      setButtonLoading(ELEMENT_IDS.PREPARE_TX_BUTTON, true);
      
      const to = document.getElementById(ELEMENT_IDS.DESTINATION_ADDRESS)?.value?.trim();
      const amount = parseFloat(document.getElementById(ELEMENT_IDS.AMOUNT_NITO)?.value || '0');
      
      if (!to || !amount || amount <= 0) {
        const errorMsg = getTranslation('errors.fill_destination_amount', 'Veuillez remplir l\'adresse de destination et le montant');
        alert(errorMsg);
        return;
      }
      
      if (!window.signTxWithPSBT) {
        const errorMsg = getTranslation('errors.transaction_functions_unavailable', 'Fonctions de transaction non disponibles');
        throw new Error(errorMsg);
      }
      
      // Validation renforcée pour montants élevés
      if (window.getTotalBalance) {
        const totalBal = await window.getTotalBalance();
        const feeReserve = 0.0005; // Reserve plus élevée pour les fees
        
        if (amount > (totalBal - feeReserve)) {
          const errorMsg = getTranslation('errors.amount_too_high', 
            `Montant trop élevé. Maximum: ${(totalBal - feeReserve).toFixed(8)} NITO (${feeReserve} NITO réservés pour les frais)`
          );
          throw new Error(errorMsg);
        }
      }
      
      const result = await window.signTxWithPSBT(to, amount, false);
      
      document.getElementById(ELEMENT_IDS.SIGNED_TX).textContent = result.hex;
      document.getElementById(ELEMENT_IDS.TX_HEX_CONTAINER).style.display = 'block';
      
      document.getElementById(ELEMENT_IDS.BROADCAST_TX_BUTTON).style.display = 'inline-block';
      document.getElementById(ELEMENT_IDS.CANCEL_TX_BUTTON).style.display = 'inline-block';
      
      console.log('[UI] Transaction prepared successfully');
    } catch (error) {
      const errorMsg = getTranslation('errors.transaction_prep_failed', `Échec de la préparation de la transaction: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Transaction preparation error:', error);
    } finally {
      showLoadingSpinner(false);
      setButtonLoading(ELEMENT_IDS.PREPARE_TX_BUTTON, false);
      endOperation('transaction');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.BROADCAST_TX_BUTTON, 'click', async () => {
    if (isOperationActive('broadcast')) {
      console.log('[UI] Broadcast already in progress');
      return;
    }
    
    try {
      startOperation('broadcast');
      showLoadingSpinner(true);
      setButtonLoading(ELEMENT_IDS.BROADCAST_TX_BUTTON, true);
      
      const hex = document.getElementById(ELEMENT_IDS.SIGNED_TX)?.textContent;
      if (!hex) {
        const errorMsg = getTranslation('errors.no_transaction', 'Aucune transaction à diffuser');
        alert(errorMsg);
        return;
      }
      
      if (!window.rpc) {
        const errorMsg = getTranslation('errors.rpc_unavailable', 'Fonction RPC non disponible');
        throw new Error(errorMsg);
      }
      
      const txid = await window.rpc('sendrawtransaction', [hex]);
      
      await showSuccessPopup(txid);
      
      // Clear form
      document.getElementById(ELEMENT_IDS.DESTINATION_ADDRESS).value = '';
      document.getElementById(ELEMENT_IDS.AMOUNT_NITO).value = '';
      document.getElementById(ELEMENT_IDS.TX_HEX_CONTAINER).style.display = 'none';
      document.getElementById(ELEMENT_IDS.BROADCAST_TX_BUTTON).style.display = 'none';
      document.getElementById(ELEMENT_IDS.CANCEL_TX_BUTTON).style.display = 'none';
      
      // Update balance after successful transaction
      setTimeout(() => updateBalanceWithLoading(), 2000);
      
      console.log('[UI] Transaction broadcast successfully:', txid);
    } catch (error) {
      const errorMsg = getTranslation('errors.broadcast_failed', `Échec de la diffusion: ${error.message}`);
      alert(errorMsg);
      console.error('[UI] Broadcast error:', error);
    } finally {
      showLoadingSpinner(false);
      setButtonLoading(ELEMENT_IDS.BROADCAST_TX_BUTTON, false);
      endOperation('broadcast');
    }
  });

  addUniqueEventListener(ELEMENT_IDS.CANCEL_TX_BUTTON, 'click', () => {
    document.getElementById(ELEMENT_IDS.TX_HEX_CONTAINER).style.display = 'none';
    document.getElementById(ELEMENT_IDS.BROADCAST_TX_BUTTON).style.display = 'none';
    document.getElementById(ELEMENT_IDS.CANCEL_TX_BUTTON).style.display = 'none';
    document.getElementById(ELEMENT_IDS.SIGNED_TX).textContent = '';
  });

  addUniqueEventListener(ELEMENT_IDS.COPY_TX_HEX, 'click', () => {
    copyToClipboard(ELEMENT_IDS.SIGNED_TX);
  });

  // Bouton de rafraîchissement standardisé dans l'onglet Envoyer avec déduplication
  addUniqueEventListener(ELEMENT_IDS.REFRESH_SEND_TAB_BALANCE, 'click', async () => {
    try {
      setButtonLoading(ELEMENT_IDS.REFRESH_SEND_TAB_BALANCE, true);
      await updateBalanceWithLoading();
      // Aussi mettre à jour le solde spécifique de l'onglet envoi
      if (typeof window.updateSendTabBalance === 'function' && !isOperationActive('balance-refresh')) {
        await window.updateSendTabBalance();
      }
    } catch (error) {
      console.error('[UI] Send tab balance refresh error:', error);
    } finally {
      setButtonLoading(ELEMENT_IDS.REFRESH_SEND_TAB_BALANCE, false);
    }
  });
  
  console.log('[UI] Transaction handlers setup completed');
}

// === MAIN SETUP FUNCTION ===
export function setupUIHandlers() {
  if (setupComplete) {
    console.log('[UI] Handlers already setup, skipping...');
    return true;
  }
  
  console.log('[UI] Setting up UI event handlers with enhanced deduplication...');
  
  try {
    setupGenerationHandlers();
    setupImportHandlers();
    setupAuthenticationSystem();
    setupTransactionHandlers();
    
    setupComplete = true;
    console.log('[UI] All event handlers setup completed successfully');
    return true;
  } catch (error) {
    console.error('[UI] Handlers setup failed:', error);
    setupComplete = false;
    return false;
  }
}

// === CLEANUP FUNCTION ===
export function cleanupUIHandlers() {
  console.log('[UI] Cleaning up all event handlers...');
  
  handlerRegistry.forEach((handler, key) => {
    const [elementId, eventType] = key.split(':');
    removeEventListener(elementId, eventType);
  });
  
  handlerRegistry.clear();
  setupComplete = false;
  
  console.log('[UI] All event handlers cleaned up');
}

// === AUTO-INITIALIZATION WITH BETTER TIMING ===
function initializeWhenReady() {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(setupUIHandlers, 100);
    });
  } else {
    setTimeout(setupUIHandlers, 100);
  }
}

// === RE-SETUP ON LANGUAGE CHANGE ===
if (typeof window !== 'undefined') {
  // Listen for language change events
  if (window.i18next && typeof window.i18next.on === 'function') {
    window.i18next.on('languageChanged', () => {
      console.log('[UI] Language changed, refreshing handlers...');
      setTimeout(() => {
        // Re-apply button labels without removing handlers
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

// Initialize
initializeWhenReady();

// === GLOBAL ACCESS ===
if (typeof window !== 'undefined') {
  window.setupUIHandlers = setupUIHandlers;
  window.cleanupUIHandlers = cleanupUIHandlers;
  window.updateBalance = updateBalance;
  window.updateBalanceWithLoading = updateBalanceWithLoading;
  window.showConnectionLoadingSpinner = showConnectionLoadingSpinner;
  window.addUniqueEventListener = addUniqueEventListener;
  window.removeEventListener = removeEventListener;
}

console.log('UI handlers module loaded - Version 2.0.0');
