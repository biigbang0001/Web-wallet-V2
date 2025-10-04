import { getTranslation, ELEMENT_IDS } from './config.js';
import { armInactivityTimerSafely } from './security.js';
import { getExplorerUrl, checkTransactionConfirmation } from './blockchain.js';

let _successPopupEl = null;
let _successPopupTimer = null;
let _pendingConfirmations = new Set();
let _refreshBlocked = false;
let messageProgressElement = null;

export function showLoading(message) {
  try {
    let modal = document.getElementById('loadingModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'loadingModal';
      modal.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,.35);backdrop-filter:blur(4px);z-index:9999;align-items:center;justify-content:center;';

      const isDarkMode = document.body.getAttribute('data-theme') === 'dark';
      const defaultMessage = getTranslation('progress_indicators.initializing', 'Initializing...');
      const scanningText = getTranslation('loading.blockchain_scan', 'Scanning blockchain...');
      
      modal.innerHTML = `
        <div style="
          background: ${isDarkMode ? '#1a202c' : '#ffffff'};
          color: ${isDarkMode ? '#e2e8f0' : '#111111'};
          border: 1px solid ${isDarkMode ? '#4a5568' : '#e2e8f0'};
          padding: 1.5rem 2rem;
          border-radius: 16px;
          box-shadow: 0 10px 30px rgba(0,0,0,${isDarkMode ? '0.5' : '0.2'});
          text-align: center;
          min-width: 300px;
          max-width: 90vw;
          backdrop-filter: blur(10px);
        ">
          <div style="font-size:2.5rem; line-height:1; margin-bottom:1rem; animation: rotate 1.2s linear infinite;">⏳</div>
          <div class="loading-text" style="font-weight:600; font-size: 18px; margin-bottom: 0.5rem;">${message || defaultMessage}</div>
          <div style="font-size: 14px; opacity: 0.7;">${scanningText}</div>
        </div>
      `;
      document.body.appendChild(modal);
    }
    const text = modal.querySelector('.loading-text');
    if (text && message) text.textContent = message;
    modal.style.display = 'flex';
  } catch (e) {
    console.warn('Loading modal error:', e);
  }
}

export function hideLoading() {
  try {
    const modal = document.getElementById('loadingModal');
    if (!modal) return;
    modal.style.display = 'none';
  } catch (e) {
    console.warn('Hide loading error:', e);
  }
}

export function showBalanceLoadingSpinner(show, messageKey = 'loading.balance_refresh') {
  let modal = document.getElementById('balanceLoadingModal');

  if (show) {
    const message = getTranslation(messageKey, 'Refreshing balance...');
    const subtitle = getTranslation('loading.blockchain_scan', 'Blockchain scan in progress...');

    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'balanceLoadingModal';
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
        <div style="font-size:3rem; line-height:1; margin-bottom:1.2rem; animation: rotate 1.5s linear infinite;">⏳</div>
        <div class="loading-text" style="font-weight:700; font-size: 20px; margin-bottom: 0.8rem; color: ${isDarkMode ? '#60a5fa' : '#2563eb'};">${message}</div>
        <div style="font-size: 15px; opacity: 0.8; margin-bottom: 1rem;">${subtitle}</div>
        <div style="width: 100%; background: ${isDarkMode ? '#374151' : '#e5e7eb'}; border-radius: 10px; height: 6px; overflow: hidden;">
          <div style="width: 100%; height: 100%; background: linear-gradient(90deg, ${isDarkMode ? '#3b82f6' : '#2563eb'}, ${isDarkMode ? '#1e40af' : '#1d4ed8'}); border-radius: 10px; animation: loading-bar 2s ease-in-out infinite;"></div>
        </div>
      </div>
    `;

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
  }
}

export function showSimpleProgressBar(percentage, show = true) {
  let progressEl = document.getElementById('simpleProgressBar');
  
  if (!show || percentage === null) {
    if (progressEl && progressEl.parentNode) {
      progressEl.parentNode.removeChild(progressEl);
    }
    return;
  }

  const isDarkMode = document.body.getAttribute('data-theme') === 'dark';

  if (!progressEl) {
    progressEl = document.createElement('div');
    progressEl.id = 'simpleProgressBar';
    progressEl.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      z-index: 10001;
      width: 400px;
      max-width: 80vw;
      background: ${isDarkMode ? '#1a202c' : '#ffffff'};
      padding: 20px;
      border-radius: 16px;
      box-shadow: 0 10px 30px rgba(0,0,0,${isDarkMode ? '0.6' : '0.3'});
      border: 2px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'};
    `;
    document.body.appendChild(progressEl);
  }

  progressEl.innerHTML = `
    <div style="width: 100%; background: ${isDarkMode ? '#374151' : '#e5e7eb'}; border-radius: 12px; height: 12px; overflow: hidden;">
      <div style="width: ${percentage}%; background: linear-gradient(90deg, ${isDarkMode ? '#3b82f6' : '#2563eb'}, ${isDarkMode ? '#1e40af' : '#1d4ed8'}); height: 100%; border-radius: 12px; transition: width 0.3s ease;"></div>
    </div>
  `;
}

export async function showSuccessPopup(txid) {
  armInactivityTimerSafely();

  try {
    if (_successPopupTimer) { clearTimeout(_successPopupTimer); _successPopupTimer = null; }
    if (_successPopupEl && _successPopupEl.parentNode) { _successPopupEl.parentNode.removeChild(_successPopupEl); }
  } catch (_) {}

  _pendingConfirmations.add(txid);
  _refreshBlocked = true;

  const refreshBtn = document.getElementById(ELEMENT_IDS.REFRESH_BALANCE_BUTTON);
  if (refreshBtn) {
    refreshBtn.disabled = true;
    const confirmingText = getTranslation('popup.confirming', 'Confirming...');
    refreshBtn.textContent = confirmingText;
  }

  const body = document.body;
  const isDarkMode = body.getAttribute('data-theme') === 'dark';
  let progress = 0;
  let explorerUrl;
  try {
    explorerUrl = await getExplorerUrl(txid);
  } catch (_) { explorerUrl = "#"; }

  const popup = document.createElement('div');
  popup.className = 'popup';
  popup.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: ${isDarkMode ? '#1a202c' : '#ffffff'};
    color: ${isDarkMode ? '#e2e8f0' : '#1e3a8a'};
    padding: 24px;
    border: 1px solid ${isDarkMode ? '#4a5568' : '#e2e8f0'};
    border-radius: 20px;
    box-shadow: 0 15px 40px rgba(0,0,0,${isDarkMode ? '0.6' : '0.25'});
    z-index: 100000;
    pointer-events: auto;
    min-width: 380px;
    max-width: 90vw;
    backdrop-filter: blur(15px);
    border: 2px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'};
  `;

  const _sanitize = (html) => (typeof DOMPurify !== "undefined" && DOMPurify && DOMPurify.sanitize) ? DOMPurify.sanitize(html) : html;

  const successMessage = getTranslation('popup.success_message', 'Transaction sent successfully!');
  const confirmationProgress = getTranslation('popup.confirmation_progress', 'Confirmation:');
  const transactionId = getTranslation('popup.transaction_id', 'Transaction ID:');
  const closeButton = getTranslation('popup.close_button', 'Close');

  popup.innerHTML = _sanitize(`
    <div style="text-align: center;">
      <div style="font-size: 2.5rem; margin-bottom: 1rem;">✅</div>
      <p style="margin-bottom: 20px; font-weight: 700; font-size: 18px; color: ${isDarkMode ? '#4ade80' : '#10b981'};">${successMessage}</p>
      <p style="margin-bottom: 15px; font-size: 16px; font-weight: 600;">${confirmationProgress} <span id="progress" style="font-weight: bold; color: ${isDarkMode ? '#60a5fa' : '#2563eb'};">0</span>%</p>
      <div style="width: 100%; background: ${isDarkMode ? '#374151' : '#e5e7eb'}; border-radius: 12px; height: 10px; margin: 15px 0; overflow: hidden; box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);">
        <div id="progressBar" style="width: 0%; background: linear-gradient(90deg, ${isDarkMode ? '#4ade80' : '#10b981'}, ${isDarkMode ? '#22d3ee' : '#06b6d4'}); height: 100%; border-radius: 12px; transition: width 0.5s ease; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></div>
      </div>
      <div style="margin-bottom: 20px; padding: 12px; background: ${isDarkMode ? '#374151' : '#f8fafc'}; border-radius: 10px; border: 1px solid ${isDarkMode ? '#4b5563' : '#e2e8f0'};">
        <p style="margin-bottom: 8px; font-size: 14px; font-weight: 600; color: ${isDarkMode ? '#9ca3af' : '#6b7280'};">${transactionId}</p>
        <p id="txidLink" style="font-size: 13px; word-break: break-all; font-family: 'Monaco', 'Menlo', 'Consolas', monospace; color: ${isDarkMode ? '#d1d5db' : '#374151'};">${txid}</p>
      </div>
      <button id="closeSuccessPopup" type="button" style="
        background: ${isDarkMode ? '#3b82f6' : '#2563eb'};
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 10px;
        cursor: pointer;
        font-weight: 700;
        font-size: 16px;
        transition: all 0.3s ease;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
      ">${closeButton}</button>
    </div>
  `);
  document.body.appendChild(popup);
  _successPopupEl = popup;

  const progressSpan = popup.querySelector('#progress');
  const progressBar = popup.querySelector('#progressBar');
  const txidLinkSpan = popup.querySelector('#txidLink');
  const closeButtonEl = popup.querySelector('#closeSuccessPopup');

  const clearAll = async () => {
    try { if (_successPopupTimer) clearTimeout(_successPopupTimer); } catch(_) {}
    _successPopupTimer = null;
    if (_successPopupEl && _successPopupEl.parentNode) {
      _successPopupEl.parentNode.removeChild(_successPopupEl);
    }
    _successPopupEl = null;

    _pendingConfirmations.delete(txid);
    if (_pendingConfirmations.size === 0) {
      _refreshBlocked = false;
      if (refreshBtn) {
        refreshBtn.disabled = false;
        const refreshText = getTranslation('import_section.refresh_button', 'Refresh');
        refreshBtn.textContent = refreshText;
      }
    }

    if (progress >= 100) {
      console.log('[POPUP] Transaction was confirmed, starting intelligent refresh...');

      setTimeout(async () => {
        if (window.refreshAllBalances) {
          let balanceFound = false;

          for (let attempt = 1; attempt <= 3; attempt++) {
            console.log(`[POPUP] Balance refresh attempt ${attempt}/3 after popup close...`);

            await window.refreshAllBalances();

            if (window.getTotalBalance) {
              const currentBalance = await window.getTotalBalance();
              console.log(`[POPUP] Current balance: ${currentBalance.toFixed(8)} NITO`);

              if (currentBalance > 0) {
                console.log(`[POPUP] Balance refreshed successfully on attempt ${attempt}`);
                balanceFound = true;
                break;
              }
            }

            if (attempt < 3) {
              console.log(`[POPUP] Balance still 0, waiting 3 seconds before retry...`);
              await new Promise(resolve => setTimeout(resolve, 3000));
            }
          }

          if (!balanceFound) {
            console.log(`[POPUP] Balance still 0 after 3 attempts, UTXOs may need more time to be indexed`);
          }
        }
      }, 500);
    }
  };

  const updateProgress = async () => {
    if (progress >= 100) return;
    progress = Math.min(progress + 1.67, 100);
    if (progressSpan) progressSpan.textContent = Math.round(progress);
    if (progressBar) progressBar.style.width = Math.round(progress) + '%';

    try {
      const confirmed = await checkTransactionConfirmation(txid);
      if (confirmed) {
        progress = 100;
        if (progressSpan) {
          progressSpan.textContent = progress;
          progressSpan.style.color = isDarkMode ? '#4ade80' : '#10b981';
        }
        if (progressBar) {
          progressBar.style.width = '100%';
          progressBar.style.background = isDarkMode ? '#4ade80' : '#10b981';
        }
        if (txidLinkSpan) {
          txidLinkSpan.innerHTML = `<a href="${explorerUrl}" target="_blank" rel="noopener noreferrer" style="color: ${isDarkMode ? '#60a5fa' : '#2563eb'}; text-decoration: underline; font-weight: 600;">${txid}</a>`;
        }

        return;
      }
    } catch (_) {}
    _successPopupTimer = setTimeout(updateProgress, 10000);
  };

  updateProgress();

  if (closeButtonEl) {
    closeButtonEl.onclick = (e) => { e.preventDefault(); e.stopPropagation(); clearAll(); };
    closeButtonEl.onmouseover = () => { closeButtonEl.style.transform = 'translateY(-2px)'; closeButtonEl.style.boxShadow = '0 6px 16px rgba(59, 130, 246, 0.6)'; };
    closeButtonEl.onmouseout = () => { closeButtonEl.style.transform = 'translateY(0)'; closeButtonEl.style.boxShadow = '0 4px 12px rgba(59, 130, 246, 0.4)'; };
  }

  const onKey = (e) => {
    if (e.key === 'Escape') { clearAll(); document.removeEventListener('keydown', onKey); }
  };
  document.addEventListener('keydown', onKey);
}

export async function showConsolidationConfirmPopup(utxoCount, batches) {
  return new Promise((resolve) => {
    const body = document.body;
    const isDarkMode = body.getAttribute('data-theme') === 'dark';

    const popup = document.createElement('div');
    popup.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: ${isDarkMode ? '#1a202c' : '#ffffff'};
      color: ${isDarkMode ? '#e2e8f0' : '#1e3a8a'};
      padding: 2rem;
      border: 2px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'};
      border-radius: 20px;
      box-shadow: 0 15px 40px rgba(0,0,0,${isDarkMode ? '0.6' : '0.25'});
      z-index: 100000;
      min-width: 380px;
      max-width: 90vw;
      backdrop-filter: blur(15px);
      text-align: center;
    `;

    const broadcastText = getTranslation('send_section.broadcast_button', 'Broadcast transaction');
    const cancelText = getTranslation('send_section.cancel_button', 'Cancel');

    popup.innerHTML = `
      <div style="font-size: 2.5rem; margin-bottom: 1rem;">⚙️</div>
      <div style="font-size: 1.5rem; font-weight: 700; margin-bottom: 1.5rem;">
        ${utxoCount} UTXOs → ${batches} UTXO${batches > 1 ? 's' : ''}
      </div>
      <div style="display: flex; gap: 1rem; justify-content: center;">
        <button id="confirmConsolidation" style="
          background: ${isDarkMode ? '#3b82f6' : '#2563eb'};
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 10px;
          cursor: pointer;
          font-weight: 700;
          transition: all 0.3s ease;
          box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        ">${broadcastText}</button>
        <button id="cancelConsolidation" style="
          background: ${isDarkMode ? '#dc2626' : '#ef4444'};
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 10px;
          cursor: pointer;
          font-weight: 700;
          transition: all 0.3s ease;
          box-shadow: 0 4px 12px rgba(220, 38, 38, 0.4);
        ">${cancelText}</button>
      </div>
    `;

    document.body.appendChild(popup);

    const confirmBtn = document.getElementById('confirmConsolidation');
    const cancelBtn = document.getElementById('cancelConsolidation');

    confirmBtn.onclick = () => {
      document.body.removeChild(popup);
      resolve(true);
    };

    cancelBtn.onclick = () => {
      document.body.removeChild(popup);
      resolve(false);
    };

    confirmBtn.onmouseover = () => {
      confirmBtn.style.transform = 'translateY(-2px)';
      confirmBtn.style.boxShadow = '0 6px 16px rgba(59, 130, 246, 0.6)';
    };

    confirmBtn.onmouseout = () => {
      confirmBtn.style.transform = 'translateY(0)';
      confirmBtn.style.boxShadow = '0 4px 12px rgba(59, 130, 246, 0.4)';
    };

    cancelBtn.onmouseover = () => {
      cancelBtn.style.transform = 'translateY(-2px)';
      cancelBtn.style.boxShadow = '0 6px 16px rgba(220, 38, 38, 0.6)';
    };

    cancelBtn.onmouseout = () => {
      cancelBtn.style.transform = 'translateY(0)';
      cancelBtn.style.boxShadow = '0 4px 12px rgba(220, 38, 38, 0.4)';
    };
  });
}

export function showInfoPopup(message) {
  return new Promise((resolve) => {
    const body = document.body;
    const isDarkMode = body.getAttribute('data-theme') === 'dark';

    const popup = document.createElement('div');
    popup.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: ${isDarkMode ? '#1a202c' : '#ffffff'};
      color: ${isDarkMode ? '#e2e8f0' : '#1e3a8a'};
      padding: 2rem;
      border: 2px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'};
      border-radius: 20px;
      box-shadow: 0 15px 40px rgba(0,0,0,${isDarkMode ? '0.6' : '0.25'});
      z-index: 100000;
      min-width: 380px;
      max-width: 90vw;
      backdrop-filter: blur(15px);
      text-align: center;
    `;

    const okText = getTranslation('popup.ok_button', 'OK');

    popup.innerHTML = `
      <div style="font-size: 2.5rem; margin-bottom: 1rem;">ℹ️</div>
      <div style="font-size: 1.2rem; font-weight: 600; margin-bottom: 1.5rem; color: ${isDarkMode ? '#e2e8f0' : '#1e3a8a'};">
        ${message}
      </div>
      <button id="closeInfoPopup" style="
        background: ${isDarkMode ? '#3b82f6' : '#2563eb'};
        color: white;
        border: none;
        padding: 12px 32px;
        border-radius: 10px;
        cursor: pointer;
        font-weight: 700;
        font-size: 16px;
        transition: all 0.3s ease;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
      ">${okText}</button>
    `;

    document.body.appendChild(popup);

    const closeBtn = document.getElementById('closeInfoPopup');

    closeBtn.onclick = () => {
      document.body.removeChild(popup);
      resolve();
    };

    closeBtn.onmouseover = () => {
      closeBtn.style.transform = 'translateY(-2px)';
      closeBtn.style.boxShadow = '0 6px 16px rgba(59, 130, 246, 0.6)';
    };

    closeBtn.onmouseout = () => {
      closeBtn.style.transform = 'translateY(0)';
      closeBtn.style.boxShadow = '0 4px 12px rgba(59, 130, 246, 0.4)';
    };
  });
}

export function createMessageProgressIndicator() {
  if (messageProgressElement && messageProgressElement.parentNode) {
    messageProgressElement.parentNode.removeChild(messageProgressElement);
  }

  const isDarkMode = document.body.getAttribute('data-theme') === 'dark';

  messageProgressElement = document.createElement('div');
  messageProgressElement.id = 'messageProgress';
  messageProgressElement.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 100000;
    background: ${isDarkMode ? '#1a202c' : '#ffffff'};
    padding: 24px;
    border-radius: 16px;
    box-shadow: 0 10px 30px rgba(0,0,0,${isDarkMode ? '0.6' : '0.3'});
    min-width: 420px;
    max-width: 90vw;
    border: 2px solid ${isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'};
    backdrop-filter: blur(15px);
  `;
  document.body.appendChild(messageProgressElement);
  return messageProgressElement;
}

export function updateMessageProgress(current, total, action = 'Processing...') {
  if (!messageProgressElement) {
    createMessageProgressIndicator();
  }

  const isDarkMode = document.body.getAttribute('data-theme') === 'dark';
  const percentage = Math.round((current / total) * 100);

  messageProgressElement.innerHTML = `
    <div style="text-align: center;">
      <div style="margin-bottom: 16px; font-weight: 700; font-size: 18px; color: ${isDarkMode ? '#e2e8f0' : '#1e3a8a'};">
        ${action}
      </div>
      <div style="margin-bottom: 12px; font-size: 24px; font-weight: 700; color: ${isDarkMode ? '#60a5fa' : '#2563eb'};">
        ${percentage}%
      </div>
      <div style="width: 100%; background: ${isDarkMode ? '#374151' : '#e5e7eb'}; border-radius: 12px; height: 12px; overflow: hidden; box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);">
        <div style="width: ${percentage}%; background: linear-gradient(90deg, ${isDarkMode ? '#3b82f6' : '#2563eb'}, ${isDarkMode ? '#1e40af' : '#1d4ed8'}); height: 100%; border-radius: 12px; transition: width 0.3s ease; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></div>
      </div>
    </div>
  `;
}

export function closeMessageProgress(delayMs = 0) {
  if (messageProgressElement) {
    setTimeout(() => {
      if (messageProgressElement && messageProgressElement.parentNode) {
        messageProgressElement.parentNode.removeChild(messageProgressElement);
        messageProgressElement = null;
      }
    }, delayMs);
  }
}

export function showScanProgress(current, total) {
  if (!messageProgressElement) {
    createMessageProgressIndicator();
  }

  const isDarkMode = document.body.getAttribute('data-theme') === 'dark';
  const percentage = Math.round((current / total) * 100);
  const analyzingText = getTranslation('messaging.analyzing_messages', 'Analyzing messages');
  const transactionsText = getTranslation('messaging.transactions', 'transactions');

  messageProgressElement.innerHTML = `
    <div style="text-align: center;">
      <div style="margin-bottom: 16px; font-weight: 700; font-size: 18px; color: ${isDarkMode ? '#e2e8f0' : '#1e3a8a'};">
        ${analyzingText}
      </div>
      <div style="margin-bottom: 8px; font-size: 15px; color: ${isDarkMode ? '#cbd5e0' : '#6b7280'};">
        ${current}/${total} ${transactionsText}
      </div>
      <div style="margin-bottom: 12px; font-size: 24px; font-weight: 700; color: ${isDarkMode ? '#60a5fa' : '#2563eb'};">
        ${percentage}%
      </div>
      <div style="width: 100%; background: ${isDarkMode ? '#374151' : '#e5e7eb'}; border-radius: 12px; height: 12px; overflow: hidden; box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);">
        <div style="width: ${percentage}%; background: linear-gradient(90deg, ${isDarkMode ? '#48bb78' : '#10b981'}, ${isDarkMode ? '#68d391' : '#22c55e'}); height: 100%; border-radius: 12px; transition: width 0.3s ease; box-shadow: 0 2px 4px rgba(0,0,0,0.2);"></div>
      </div>
    </div>
  `;
}

export function showMessageModal(messageId, senderAddress, messageBody) {
  const modal = document.getElementById('msgModal');
  const msgFrom = document.getElementById('msgFrom');
  const msgBody = document.getElementById('msgBody');

  if (modal && msgFrom && msgBody) {
    msgFrom.textContent = senderAddress;
    msgBody.textContent = messageBody;
    modal.style.display = 'block';

    const closeButtons = modal.querySelectorAll('[data-close]');
    closeButtons.forEach(btn => {
      btn.onclick = () => {
        modal.style.display = 'none';
      };
    });
  }
}

export function showCopyFeedback(success, message = null) {
  const text = success
    ? getTranslation('security.copied', 'Copied!')
    : (message || getTranslation('security.copy_failed', 'Copy failed'));

  if (window.showNotification) {
    window.showNotification(text, success ? 'success' : 'error');
  } else {
    alert(text);
  }
}

if (typeof window !== 'undefined') {
  window.showLoading = showLoading;
  window.hideLoading = hideLoading;
  window.showBalanceLoadingSpinner = showBalanceLoadingSpinner;
  window.showSimpleProgressBar = showSimpleProgressBar;
  window.showSuccessPopup = showSuccessPopup;
  window.showConsolidationConfirmPopup = showConsolidationConfirmPopup;
  window.showInfoPopup = showInfoPopup;
  window.showMessageModal = showMessageModal;
  window.createMessageProgressIndicator = createMessageProgressIndicator;
  window.updateMessageProgress = updateMessageProgress;
  window.closeMessageProgress = closeMessageProgress;
  window.showScanProgress = showScanProgress;
}