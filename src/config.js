// === VERSION INFORMATION ===
export const VERSION = {
  MAJOR: 3,
  MINOR: 0,
  PATCH: 0,
  BUILD: Date.now(),
  STRING: '3.0.0'
};

// === NETWORK CONFIGURATION ===
export const NITO_NETWORK = {
  messagePrefix: '\x18NITO Signed Message:\n',
  bech32: 'nito',
  bip32: { 
    public: 0x0488B21E, 
    private: 0x0488ADE4 
  },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80
};

// === NODE CONFIGURATION ===
export const NODE_CONFIG = {
  URL: '/api/',
  DEBUG: false,
  TIMEOUT: 600000,
  MAX_RETRIES: 5,
  RETRY_DELAY: 2000,
  ERROR_500_DELAY: 2000,
  NO_503_BACKOFF_METHODS: new Set(['getrawmempool', 'getrawtransaction', 'getmempoolinfo'])
};

// === HD WALLET CONFIGURATION ===
export const HD_CONFIG = {
  DERIVATION_PATHS: {
    legacy: "m/44'/0'/0'",
    p2sh: "m/49'/0'/0'",
    bech32: "m/84'/0'/0'",
    taproot: "m/86'/0'/0'"
  },
  START_RANGE: 512,
  MAX_RANGE: 50000,
  RANGE_SAFETY: 16,
  SCAN_CHUNK: 50,
  SCAN_MAX_CHUNKS: 40,
  DEFAULT_WORD_COUNT: 12
};

// === TRANSACTION CONFIGURATION ===
export const TRANSACTION_CONFIG = {
  MIN_FEE_RATE: 0.00001,
  DYNAMIC_FEE_RATE: 0.00001,
  MAX_UTXOS_PER_BATCH: 100,
  MAX_TX_VBYTES: 99000,
  DUST_AMOUNT: {
    p2pkh: 546,
    p2wpkh: 294,
    p2sh: 540,
    p2tr: 330
  },
  MIN_CONSOLIDATION_FEE: 0.00005,
  DUST_RELAY_AMOUNT: 3000
};

// === UTXO VALUE CONSTANTS ===
export const UTXO_VALUES = {
  MESSAGE_UTXO: 294,
  MIN_TRANSACTION: 777,
  MIN_MESSAGING: 294,
  DUST_RELAY: 3000,
  MIN_CONSOLIDATION: 546
};

// === MESSAGING CONFIGURATION ===
export const MESSAGING_CONFIG = {
  CHUNK_SIZE: 66,
  MESSAGE_PREFIX: 'NM',
  PUBKEY_PREFIX: 'NP:',
  MAX_MESSAGE_LENGTH: 50000,
  MESSAGE_FEE: 0.00000294,
  PROTECTION_LIMIT: 0.00005,
  COMPRESSION_LEVEL: 9,
  CHUNK_AMOUNT_MULTIPLIER: 1.2,
  ALLOWED_SCRIPT_TYPES: ['p2wpkh'],
  BECH32_SCRIPTPUBKEY_PATTERN: /^0014[a-fA-F0-9]{40}$/
};

// === SECURITY CONFIGURATION ===
export const SECURITY_CONFIG = {
  SESSION_TIMEOUT: 600000,
  INACTIVITY_TIMEOUT: 600000,
  CLEANUP_INTERVAL: 600000,
  MAX_MEMORY_KEYS: 10,
  BLUR_TIMEOUT: 600000,
  PBKDF2_ITERATIONS: 200000,
  AES_KEY_SIZE: 32,
  AES_IV_SIZE: 12,
  RATE_LIMIT_ATTEMPTS: 5,
  RATE_LIMIT_WINDOW: 600000,
  AUTO_RELOAD_ON_CLEAR: true,
  GENERATION_KEY_TIMEOUT: 600000
};

// === UI CONFIGURATION ===
export const UI_CONFIG = {
  LANGUAGES: ['fr', 'en', 'de', 'es', 'nl', 'ru', 'zh'],
  THEMES: ['light', 'dark'],
  DEFAULT_THEME: 'light',
  AUTO_REFRESH_DELAY: 3000,
  POPUP_DURATION: 5000,
  NOTIFICATION_TIMEOUT: 60000,
  PROGRESS_UPDATE_INTERVAL: 100,
  CONFIRMATION_CHECK_INTERVAL: 10000,
  TRANSLATION_RETRY_ATTEMPTS: 3,
  TRANSLATION_RETRY_DELAY: 1000
};

// === API CONFIGURATION ===
export const API_CONFIG = {
  COUNTER_GET_URL: '/api/get-counter.php',
  COUNTER_INCREMENT_URL: '/api/get-counter.php',
  EXPLORER_PRIMARY: 'https://explorer.nito.network',
  EXPLORER_FALLBACK: 'https://nitoexplorer.org',
  REQUEST_TIMEOUT: 10000,
  MAX_RETRIES: 3
};

// === DOM ELEMENT IDS ===
export const ELEMENT_IDS = {
  LOADING_SPINNER: 'loadingSpinner',
  THEME_TOGGLE: 'themeToggle',
  LANGUAGE_SELECT: 'languageSelect',
  
  GENERATE_BUTTON: 'generateButton',
  HD_MASTER_KEY: 'hdMasterKey',
  MNEMONIC_PHRASE: 'mnemonicPhrase',
  REVEAL_HD_KEY: 'revealHdKey',
  REVEAL_MNEMONIC: 'revealMnemonic',
  COPY_HD_KEY: 'copyHdKey',
  COPY_MNEMONIC: 'copyMnemonic',
  GENERATED_ADDRESS: 'generatedAddress',
  INACTIVITY_TIMER: 'inactivityTimer',
  KEY_COUNTER: 'keyCounter',
  
  IMPORT_WALLET_BUTTON: 'importWalletButton',
  CONNECT_EMAIL_BUTTON: 'connectEmailButton',
  EMAIL_SEED_BUTTON: 'emailSeedButton',
  PRIVATE_KEY_WIF: 'privateKeyWIF',
  EMAIL_INPUT: 'emailInput',
  PASSWORD_INPUT: 'passwordInput',
  EMAIL_INPUTS: 'emailInputs',
  EMAIL_FORM: 'emailForm',
  KEY_FORM: 'keyForm',
  TAB_EMAIL: 'tabEmail',
  TAB_KEY: 'tabKey',
  
  WALLET_ADDRESS: 'walletAddress',
  REFRESH_BALANCE_BUTTON: 'refreshBalanceButton',
  BECH32_ADDRESS: 'bech32Address',
  TAPROOT_ADDRESS: 'taprootAddress',
  
  DESTINATION_ADDRESS: 'destinationAddress',
  AMOUNT_NITO: 'amountNito',
  FEE_NITO: 'feeNito',
  MAX_BUTTON: 'maxButton',
  DEBIT_ADDRESS_TYPE: 'debitAddressType',
  SEND_TAB_BALANCE: 'sendTabBalance',
  REFRESH_SEND_TAB_BALANCE: 'refreshSendTabBalance',
  PREPARE_TX_BUTTON: 'prepareTxButton',
  BROADCAST_TX_BUTTON: 'broadcastTxButton',
  CANCEL_TX_BUTTON: 'cancelTxButton',
  SIGNED_TX: 'signedTx',
  TX_HEX_CONTAINER: 'txHexContainer',
  COPY_TX_HEX: 'copyTxHex',
  CONSOLIDATE_BUTTON: 'consolidateButton',
  
  PUBLISH_PUBKEY_BUTTON: 'publishPubkeyButton',
  MESSAGE_INPUT: 'messageInput',
  MESSAGE_CHAR_COUNTER: 'messageCharCounter',
  SEND_MESSAGE_BUTTON: 'sendMessageButton',
  CLEAR_MESSAGE_BUTTON: 'clearMessageButton',
  SEND_MESSAGE_FORM: 'sendMessageForm',
  RECIPIENT_ADDRESS: 'recipientAddress',
  SEND_MESSAGE_COST: 'sendMessageCost',
  CONFIRM_SEND_BUTTON: 'confirmSendButton',
  CANCEL_SEND_BUTTON: 'cancelSendButton',
  REFRESH_MESSAGES_BUTTON: 'refreshMessagesButton',
  UNREAD_MESSAGES: 'unreadMessages',
  UNREAD_COUNT: 'unreadCount',
  MESSAGE_LIST: 'messageList',
  
  MSG_MODAL: 'msgModal',
  MSG_FROM: 'msgFrom',
  MSG_BODY: 'msgBody'
};

// === VALIDATION PATTERNS ===
export const VALIDATION_PATTERNS = {
  BECH32_ADDRESS: /^nito1[02-9ac-hj-np-z]{6,87}$/,
  BECH32M_ADDRESS: /^nito1p[02-9ac-hj-np-z]{6,87}$/,
  LEGACY_ADDRESS: /^[13][1-9A-HJ-NP-Za-km-z]{25,39}$/,
  ADDRESS: /^(nito1[02-9ac-hj-np-z]{6,87}|[13][1-9A-HJ-NP-Za-km-z]{25,39})$/,
  WIF: /^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$/,
  HEX_PRIVATE_KEY: /^[0-9a-fA-F]{64}$/,
  XPRV: /^xprv[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/,
  SCRIPT_HEX: /^[0-9a-fA-F]*$/,
  TXID: /^[0-9a-fA-F]{64}$/,
  AMOUNT: /^\d+(\.\d{1,8})?$/,
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
};

// === ERROR CODES ===
export const ERROR_CODES = {
  WALLET_NOT_INITIALIZED: 'WALLET_NOT_INITIALIZED',
  INVALID_PRIVATE_KEY: 'INVALID_PRIVATE_KEY',
  INVALID_MNEMONIC: 'INVALID_MNEMONIC',
  INVALID_XPRV: 'INVALID_XPRV',
  INSUFFICIENT_FUNDS: 'INSUFFICIENT_FUNDS',
  INVALID_ADDRESS: 'INVALID_ADDRESS',
  INVALID_AMOUNT: 'INVALID_AMOUNT',
  DUST_AMOUNT: 'DUST_AMOUNT',
  NO_UTXOS: 'NO_UTXOS',
  UTXO_OPRETURN_CONSOLIDATE: 'UTXO_OPRETURN_CONSOLIDATE',
  RPC_ERROR: 'RPC_ERROR',
  CONNECTION_ERROR: 'CONNECTION_ERROR',
  TIMEOUT_ERROR: 'TIMEOUT_ERROR',
  NODE_CONNECTION: 'NODE_CONNECTION',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  RATE_LIMITED: 'RATE_LIMITED',
  ENCRYPTION_ERROR: 'ENCRYPTION_ERROR',
  IMPORT_FIRST: 'IMPORT_FIRST',
  MESSAGE_TOO_LONG: 'MESSAGE_TOO_LONG',
  RECIPIENT_PUBKEY_NOT_FOUND: 'RECIPIENT_PUBKEY_NOT_FOUND',
  INVALID_MESSAGE_FORMAT: 'INVALID_MESSAGE_FORMAT',
  NON_BECH32_MESSAGING: 'NON_BECH32_MESSAGING',
  ELEMENT_NOT_FOUND: 'ELEMENT_NOT_FOUND',
  REVEAL_TO_COPY: 'REVEAL_TO_COPY',
  NOTHING_TO_COPY: 'NOTHING_TO_COPY',
  COPY_ERROR: 'COPY_ERROR',
  INVALID_FIELDS: 'INVALID_FIELDS',
  FILL_ALL_FIELDS: 'FILL_ALL_FIELDS',
  ENTER_MESSAGE: 'ENTER_MESSAGE',
  INVALID_BECH32: 'INVALID_BECH32',
  TAPROOT_NOT_SUPPORTED: 'TAPROOT_NOT_SUPPORTED',
  OPERATION_IN_PROGRESS: 'OPERATION_IN_PROGRESS'
};

// === FEATURE FLAGS ===
export const FEATURE_FLAGS = {
  HD_WALLET_ENABLED: true,
  TAPROOT_ENABLED: true,
  MESSAGING_ENABLED: true,
  CONSOLIDATION_ENABLED: true,
  DEBUG_MODE: false,
  VERBOSE_LOGGING: true,
  FORCE_BECH32_MESSAGING: true,
  REQUIRE_SIGNATURE_VERIFICATION: true,
  AUTO_CLEANUP_ENABLED: true,
  LOG_ADDRESSES: true,
  AUTO_RELOAD_ON_KEY_CLEAR: true
};

// === EXTERNAL LIBRARY URLS ===
export const LIBRARY_URLS = {
  BITCOIN_JS: 'https://esm.sh/bitcoinjs-lib@6.1.6?bundle',
  ECPAIR: 'https://esm.sh/ecpair@3.0.0',
  BIP39: 'https://esm.sh/bip39@3.1.0',
  BIP32: 'https://esm.sh/bip32@4.0.0',
  SECP256K1_LAB: 'https://esm.sh/@bitcoinerlab/secp256k1@1.0.5',
  NOBLE_SECP256K1: 'https://esm.sh/@noble/secp256k1@1.7.1',
  BUFFER: 'https://esm.sh/buffer@6.0.3'
};

// === OPERATIONAL STATE TRACKING ===
export const OPERATION_STATE = {
  activeOperations: new Set(),
  isTransactionInProgress: false,
  isConsolidationInProgress: false,
  isBalanceRefreshInProgress: false,
  isMessagingInProgress: false
};

// === UNIFIED CONFIGURATION EXPORT ===
export const CONFIG = {
  VERSION,
  NETWORK: NITO_NETWORK,
  NODE: NODE_CONFIG,
  HD: HD_CONFIG,
  TRANSACTION: TRANSACTION_CONFIG,
  MESSAGING: MESSAGING_CONFIG,
  SECURITY: SECURITY_CONFIG,
  UI: UI_CONFIG,
  API: API_CONFIG,
  ELEMENT_IDS,
  VALIDATION: VALIDATION_PATTERNS,
  ERRORS: ERROR_CODES,
  FEATURES: FEATURE_FLAGS,
  LIBRARIES: LIBRARY_URLS,
  OPERATIONS: OPERATION_STATE,
  UTXO_VALUES
};

// === UTILITY FUNCTIONS ===
export function sleep(ms) { 
  return new Promise(resolve => setTimeout(resolve, ms)); 
}

export async function sleepJitter(baseMs = 1, maxJitterMs = 300, active = false) {
  const extra = active ? Math.floor(Math.random() * (maxJitterMs + 1)) : 0;
  await sleep(baseMs + extra);
}

export function getTranslation(key, fallback, params = {}) {
  const t = (window.i18next && typeof window.i18next.t === 'function') 
    ? window.i18next.t 
    : () => fallback || key;
  return t(key, { ...params, defaultValue: fallback });
}

// === GLOBAL COMPATIBILITY ===
if (typeof window !== 'undefined') {
  if (!window.NITO_NETWORK) {
    window.NITO_NETWORK = NITO_NETWORK;
  }
  if (!window.DYNAMIC_FEE_RATE) {
    window.DYNAMIC_FEE_RATE = TRANSACTION_CONFIG.DYNAMIC_FEE_RATE;
  }
  window.getTranslation = getTranslation;
  window.sleep = sleep;
  window.sleepJitter = sleepJitter;
}

console.log(`NITO Wallet Config loaded - Version ${VERSION.STRING}`);