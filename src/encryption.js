import { getTranslation } from './config.js';

class MemoryEncryption {
  constructor() {
    this.sessionKey = null;
    this.initialized = false;
    this.initPromise = null;
  }

  async initialize() {
    if (this.initPromise) return this.initPromise;
    if (this.initialized) return;
    
    this.initPromise = (async () => {
      const keyMaterial = crypto.getRandomValues(new Uint8Array(32));
      
      this.sessionKey = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      
      this.initialized = true;
      keyMaterial.fill(0);
    })();
    
    await this.initPromise;
    this.initPromise = null;
  }

  async encrypt(data) {
    if (!this.initialized) {
      await this.initialize();
    }

    let bytes;
    if (typeof data === 'string') {
      bytes = new TextEncoder().encode(data);
    } else if (data instanceof Uint8Array || data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data);
    } else if (Buffer.isBuffer(data)) {
      bytes = new Uint8Array(data);
    } else {
      throw new Error(getTranslation('security.invalid_data_type', 'Invalid data type for encryption'));
    }

    const iv = crypto.getRandomValues(new Uint8Array(12));

    try {
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        this.sessionKey,
        bytes
      );

      const result = new Uint8Array(iv.length + encrypted.byteLength);
      result.set(iv, 0);
      result.set(new Uint8Array(encrypted), iv.length);

      bytes.fill(0);

      return result;
    } catch (error) {
      bytes.fill(0);
      throw new Error(getTranslation('security.encryption_failed', 'Encryption failed: {{error}}', { error: error.message }));
    }
  }

  async decrypt(encryptedData) {
    if (!this.initialized) {
      throw new Error(getTranslation('security.encryption_not_initialized', 'Encryption not initialized - cannot decrypt without key'));
    }

    if (!(encryptedData instanceof Uint8Array)) {
      encryptedData = new Uint8Array(encryptedData);
    }

    if (encryptedData.length < 12) {
      throw new Error(getTranslation('security.invalid_encrypted_data', 'Invalid encrypted data'));
    }

    const iv = encryptedData.slice(0, 12);
    const data = encryptedData.slice(12);

    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        this.sessionKey,
        data
      );

      return new Uint8Array(decrypted);
    } catch (error) {
      throw new Error(getTranslation('security.decryption_failed', 'Decryption failed: {{error}}', { error: error.message }));
    }
  }

  async encryptString(text) {
    const encrypted = await this.encrypt(text);
    return btoa(String.fromCharCode(...encrypted));
  }

  async decryptString(base64) {
    const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    const decrypted = await this.decrypt(bytes);
    return new TextDecoder().decode(decrypted);
  }

  destroy() {
    this.sessionKey = null;
    this.initialized = false;
    this.initPromise = null;
  }
}

export const memoryEncryption = new MemoryEncryption();

if (typeof window !== 'undefined') {
  memoryEncryption.initialize().catch(err => {
    console.error('[ENCRYPTION] Auto-initialization failed:', err);
  });
}