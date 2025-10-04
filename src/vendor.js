// src/vendor.js

let librariesLoaded = false;
let loadingPromise = null;

// Fonction principale de chargement
export async function loadExternalLibraries() {
  if (loadingPromise) return loadingPromise;
  if (librariesLoaded) return true;

  loadingPromise = (async () => {
    console.log('[VENDOR] Checking local vendor bundle...');
    
    if (!window.librariesLoaded) {
      throw new Error('vendor-bundle.min.js not loaded! Check index.html');
    }
    
    if (!window.verifyLibraries || !window.verifyLibraries()) {
      throw new Error('Libraries verification failed');
    }
    
    librariesLoaded = true;
    console.log('[VENDOR] All libraries loaded from local bundle');
    return true;
  })().catch(err => {
    librariesLoaded = false;
    throw err;
  });

  return loadingPromise;
}

export function areLibrariesReady() { 
  return librariesLoaded && window.librariesLoaded === true;
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

// Récupération centralisée des bibliothèques
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

// Getters sécurisés
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

// Exposition globale
if (typeof window !== 'undefined') {
  window.getBitcoinLibraries = getBitcoinLibraries;
}

export default loadExternalLibraries;
