// === Global shims ===
if (!('global' in window)) window.global = window;
if (!('process' in window)) window.process = { env: {} };
if (!window.process.env) window.process.env = {};

let librariesLoaded = false;
let loadingPromise = null;

// === Generic single importer ===
async function importOne(name, url, attach, check) {
  const mod = await import(/* @vite-ignore */ url);
  await attach(mod);
  if (!check()) throw new Error(`Failed to load ${name}`);
  console.log(`Loaded ${name}: ${url}`);
}

// === UI libraries ===
async function loadI18next() {
  if (window.i18next && window.i18nextHttpBackend) return;
  await importOne(
    'i18next',
    'https://esm.sh/i18next@23.15.1',
    async (mod) => { window.i18next = mod?.default || mod; },
    () => !!window.i18next?.use
  );
  await importOne(
    'i18next-http-backend',
    'https://esm.sh/i18next-http-backend@2.6.1',
    async (mod) => { window.i18nextHttpBackend = mod?.default || mod; },
    () => !!window.i18nextHttpBackend
  );
}

async function loadDOMPurify() {
  if (window.DOMPurify?.sanitize) return window.DOMPurify;
  await importOne(
    'DOMPurify',
    'https://esm.sh/dompurify@3.1.6',
    async (mod) => {
      const create = mod?.default || mod?.createDOMPurify || mod;
      const purifier = create(window);
      window.DOMPurify = purifier;
    },
    () => !!window.DOMPurify?.sanitize
  );
  return window.DOMPurify;
}

// === Bitcoin stack ===
async function loadBuffer() {
  if (window.Buffer?.from) return window.Buffer;
  await importOne(
    'Buffer',
    'https://esm.sh/buffer@6.0.3',
    async (mod) => {
      const B = mod?.Buffer || mod?.default?.Buffer || mod?.default;
      if (B?.from) { window.Buffer = B; globalThis.Buffer = B; }
    },
    () => !!window.Buffer?.from
  );
  return window.Buffer;
}

async function loadNoble() {
  if (window.nobleSecp?.sign) return window.nobleSecp;
  await importOne(
    'noble-secp256k1',
    'https://esm.sh/@noble/secp256k1@1.7.1',
    async (mod) => { 
      window.nobleSecp = mod?.default || mod; 
      window.secp256k1 = window.nobleSecp;
    },
    () => !!window.nobleSecp?.sign
  );
  return window.nobleSecp;
}

async function loadBitcoinerlabECC() {
  if (window.ecc?.sign) return window.ecc;
  await importOne(
    'secp256k1-ecc',
    'https://esm.sh/@bitcoinerlab/secp256k1@1.0.5',
    async (mod) => { const ecc = mod?.default || mod; if (ecc?.sign) window.ecc = ecc; },
    () => !!window.ecc?.sign
  );
  return window.ecc;
}

async function loadBitcoinJs() {
  if (window.bitcoin?.payments) return window.bitcoin;
  await importOne(
    'bitcoinjs-lib',
    'https://esm.sh/bitcoinjs-lib@6.1.6?bundle',
    async (mod) => { window.bitcoin = mod?.default || mod; },
    () => !!window.bitcoin?.payments
  );
  return window.bitcoin;
}

async function loadECPairFactory() {
  if (window.ECPairFactory) return window.ECPairFactory;
  await importOne(
    'ecpair',
    'https://esm.sh/ecpair@3.0.0',
    async (mod) => { window.ECPairFactory = mod?.default || mod?.ECPairFactory || mod; },
    () => typeof window.ECPairFactory === 'function'
  );
  return window.ECPairFactory;
}

async function loadBip39() {
  if (window.bip39?.generateMnemonic) return window.bip39;
  await importOne(
    'bip39',
    'https://esm.sh/bip39@3.1.0',
    async (mod) => { window.bip39 = mod?.default || mod; },
    () => !!window.bip39?.generateMnemonic
  );
  return window.bip39;
}

async function loadBip32Factory() {
  if (window.__bip32Factory) return window.__bip32Factory;
  await importOne(
    'bip32-factory',
    'https://esm.sh/bip32@4.0.0',
    async (mod) => { window.__bip32Factory = mod?.default || mod?.BIP32Factory || mod; },
    () => typeof window.__bip32Factory === 'function'
  );
  return window.__bip32Factory;
}

// === ECC initialization ===
async function initializeECC() {
  const ecc = await loadBitcoinerlabECC();
  const bitcoin = await loadBitcoinJs();

  if (!bitcoin?.initEccLib || !ecc?.sign) throw new Error('ECC init failed');
  bitcoin.initEccLib(ecc);

  const ECPairFactory = await loadECPairFactory();
  window.ECPair = ECPairFactory(ecc);

  const bip32Factory = await loadBip32Factory();
  window.bip32 = bip32Factory(ecc);
  if (!window.bip32?.fromSeed) throw new Error('bip32 init failed');
}

// === Public API ===
export async function loadExternalLibraries() {
  if (loadingPromise) return loadingPromise;
  if (librariesLoaded) return true;

  loadingPromise = (async () => {
    console.log('Loading external Bitcoin libraries...');
    await loadDOMPurify();
    await loadI18next();
    await loadBuffer();
    await loadNoble();
    await initializeECC();
    await loadBip39();

    if (
      !window.DOMPurify?.sanitize ||
      !window.i18next?.use ||
      !window.i18nextHttpBackend ||
      !window.Buffer?.from ||
      !window.bitcoin?.payments ||
      !window.ecc?.sign ||
      !window.ECPair?.makeRandom ||
      !window.bip39?.generateMnemonic ||
      !window.bip32?.fromSeed ||
      !window.secp256k1?.sign
    ) {
      throw new Error('One or more libraries are missing after load');
    }

    librariesLoaded = true;
    window.dispatchEvent(new CustomEvent('bitcoinLibrariesLoaded', { detail: { ts: Date.now() } }));
    return true;
  })().catch(err => {
    librariesLoaded = false;
    window.dispatchEvent(new CustomEvent('bitcoinLibrariesFailed', { detail: { error: String(err) } }));
    throw err;
  });

  return loadingPromise;
}

export function areLibrariesReady() { 
  return !!librariesLoaded; 
}

export function waitForLibraries(timeout = 60000) {
  return new Promise((resolve, reject) => {
    if (areLibrariesReady()) { 
      resolve(); 
      return; 
    }
    const tId = setTimeout(() => reject(new Error(`Timeout waiting for libraries (${timeout}ms)`)), timeout);
    const ok = () => { clearTimeout(tId); resolve(); };
    const fail = (e) => { clearTimeout(tId); reject(new Error(`Libraries failed: ${e?.detail?.error || 'unknown'}`)); };
    window.addEventListener('bitcoinLibrariesLoaded', ok, { once: true });
    window.addEventListener('bitcoinLibrariesFailed', fail, { once: true });
  });
}

// === Centralized Bitcoin libraries helper ===
export async function getBitcoinLibraries() {
  await waitForLibraries();
  
  if (!window.bitcoin || !window.ECPair || !window.bip39 || !window.bip32) {
    throw new Error('Bitcoin libraries not properly loaded');
  }
  
  return {
    bitcoin: window.bitcoin,
    ECPair: window.ECPair,
    bip39: window.bip39,
    bip32: window.bip32,
    ecc: window.ecc,
    Buffer: window.Buffer,
    secp256k1: window.secp256k1
  };
}

// === Safe getters ===
export function getBitcoinLib() { 
  if (!window.bitcoin?.payments) throw new Error('Bitcoin library not loaded'); 
  return window.bitcoin; 
}

export function getECPair() { 
  if (!window.ECPair?.makeRandom) throw new Error('ECPair not loaded'); 
  return window.ECPair; 
}

export function getBip39() { 
  if (!window.bip39?.generateMnemonic) throw new Error('BIP39 not loaded'); 
  return window.bip39; 
}

export function getBip32() { 
  if (!window.bip32?.fromSeed) throw new Error('BIP32 not loaded'); 
  return window.bip32; 
}

export function getECC() { 
  if (!window.ecc?.sign) throw new Error('ECC not loaded'); 
  return window.ecc; 
}

export function getBuffer() { 
  if (!window.Buffer?.from) throw new Error('Buffer not loaded'); 
  return window.Buffer; 
}

// === Global exposure ===
if (typeof window !== 'undefined') {
  window.getBitcoinLibraries = getBitcoinLibraries;
}

export default loadExternalLibraries;

// === Auto-load ===
const AUTO_LOAD = true;
if (AUTO_LOAD && typeof window !== 'undefined') {
  setTimeout(() => { 
    loadExternalLibraries().catch(err => console.error('Auto-loading failed:', err)); 
  }, 100);
}