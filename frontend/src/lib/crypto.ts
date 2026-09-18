export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export async function importPublicKey(publicKeyB64: string): Promise<CryptoKey> {
  const keyData = base64ToArrayBuffer(publicKeyB64);
  return crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'X25519' },
    true,
    []
  );
}

export async function deriveSharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits(
    { name: 'X25519', public: publicKey },
    privateKey,
    256
  );
}

export async function deriveMessageKey(sharedSecret: ArrayBuffer, info: string, saltBuffer: ArrayBuffer, pepper: string): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveKey']
  );

  const encoder = new TextEncoder();
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(saltBuffer),
      info: encoder.encode(info + pepper)
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptMessage(plaintext: string, key: CryptoKey): Promise<{ ciphertext: string, nonce: string }> {
  const encoder = new TextEncoder();
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    encoder.encode(plaintext)
  );

  return {
    ciphertext: arrayBufferToBase64(encrypted),
    nonce: arrayBufferToBase64(nonce.buffer)
  };
}

export async function decryptMessage(ciphertextB64: string, nonceB64: string, key: CryptoKey): Promise<string> {
  const ciphertext = base64ToArrayBuffer(ciphertextB64);
  const nonce = base64ToArrayBuffer(nonceB64);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}
