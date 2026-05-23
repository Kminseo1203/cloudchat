const Crypto = {
  async generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt']
    );
    const pub = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
    const priv = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    return {
      publicKeyB64: btoa(String.fromCharCode(...new Uint8Array(pub))),
      privateKeyB64: btoa(String.fromCharCode(...new Uint8Array(priv)))
    };
  },

  async importPublicKey(b64) {
    const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return window.crypto.subtle.importKey('spki', bin, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  },

  async importPrivateKey(b64) {
    const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return window.crypto.subtle.importKey('pkcs8', bin, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  },

  async encryptMessage(plainText, recipients) {
    const aesKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt','decrypt']);
    const rawAes = await window.crypto.subtle.exportKey('raw', aesKey);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encBody = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plainText));

    return Promise.all(recipients.map(async ({ userId, publicKeyB64 }) => {
      const pubKey = await Crypto.importPublicKey(publicKeyB64);
      const encKey = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, rawAes);
      return {
        userId,
        encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encKey))),
        encryptedBody: btoa(String.fromCharCode(...new Uint8Array(encBody))),
        iv: btoa(String.fromCharCode(...iv))
      };
    }));
  },

  async decryptMessage(payload, privateKeyB64) {
    const privKey = await Crypto.importPrivateKey(privateKeyB64);
    const encKeyBin = Uint8Array.from(atob(payload.encryptedKey), c => c.charCodeAt(0));
    const rawAes = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, encKeyBin);
    const aesKey = await window.crypto.subtle.importKey('raw', rawAes, { name: 'AES-GCM' }, false, ['decrypt']);
    const iv = Uint8Array.from(atob(payload.iv), c => c.charCodeAt(0));
    const encBody = Uint8Array.from(atob(payload.encryptedBody), c => c.charCodeAt(0));
    const dec = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, encBody);
    return new TextDecoder().decode(dec);
  },

  saveKeys(pub, priv) {
    localStorage.setItem('_mpk', pub);
    localStorage.setItem('_msk', priv);
  },

  loadKeys() {
    return { publicKeyB64: localStorage.getItem('_mpk'), privateKeyB64: localStorage.getItem('_msk') };
  }
};
