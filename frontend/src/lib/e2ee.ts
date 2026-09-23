import { apiFetch } from './api';
import { base64ToArrayBuffer, importPublicKey, deriveSharedSecret, deriveMessageKey, encryptMessage, decryptMessage } from './crypto';

interface ParsedMessage {
  content: string;
  attachments: any[];
  encrypted: boolean;
}

function lockedMessage(content: string): ParsedMessage {
  return { content, attachments: [], encrypted: true };
}

export class E2EE {
  ready = false;
  private pepper = '';
  private publicKey: string | null = null;
  private privateKey: CryptoKey | null = null;

  async init(): Promise<void> {
    await this.fetchConfig();

    this.publicKey = localStorage.getItem('e2ee_public_key');
    const privateKeyB64 = sessionStorage.getItem('e2ee_private_key_pkcs8');

    if (this.publicKey && privateKeyB64) {
      try {
        const privateKeyPkcs8 = base64ToArrayBuffer(privateKeyB64);
        this.privateKey = await crypto.subtle.importKey(
          'pkcs8',
          privateKeyPkcs8,
          { name: 'X25519' },
          false,
          ['deriveBits']
        );

        this.ready = true;
        console.log('E2EE initialized successfully');
      } catch (error) {
        console.error('Failed to initialize E2EE:', error);
        this.ready = false;
      }
    } else {
      console.warn('E2EE keys not available - please re-login to enable encryption');
      if (!this.publicKey) console.warn('Missing: e2ee_public_key');
      if (!privateKeyB64) console.warn('Missing: e2ee_private_key_pkcs8 (session) - re-login required');
      this.ready = false;
    }
  }

  private async fetchConfig(): Promise<void> {
    try {
      const response = await apiFetch('/api/e2ee/config');
      if (response.ok) {
        const config = await response.json();
        this.pepper = config.pepper || '';
      }
    } catch (error) {
      console.error('Failed to fetch E2EE config:', error);
    }
  }

  async getReceiverPublicKey(receiverEmail: string): Promise<string | null> {
    try {
      const response = await apiFetch(`/api/user/public-key?email=${encodeURIComponent(receiverEmail)}`);
      if (response.ok) {
        const data = await response.json();
        return data.e2ee_public_key || null;
      }
    } catch (error) {
      console.error('Failed to get receiver public key:', error);
    }
    return null;
  }

  private async messageKey(otherPartyPublicKeyB64: string): Promise<CryptoKey> {
    const otherPartyPublicKey = await importPublicKey(otherPartyPublicKeyB64);
    const sharedSecret = await deriveSharedSecret(this.privateKey!, otherPartyPublicKey);
    const sortedKeys = [this.publicKey!, otherPartyPublicKeyB64].sort().join('');
    const saltData = new TextEncoder().encode(sortedKeys);
    const saltHash = await crypto.subtle.digest('SHA-256', saltData);
    return deriveMessageKey(sharedSecret, 'message-encryption', saltHash, this.pepper);
  }

  async encrypt(content: string, receiverPublicKeyB64: string): Promise<{
    encryptedContent: string,
    nonce: string,
    senderPublicKey: string
  }> {
    if (!this.privateKey || !this.publicKey) {
      throw new Error('Sender keys not available');
    }

    const messageKey = await this.messageKey(receiverPublicKeyB64);
    const { ciphertext, nonce } = await encryptMessage(content, messageKey);

    return {
      encryptedContent: ciphertext,
      nonce: nonce,
      senderPublicKey: this.publicKey
    };
  }

  async decrypt(
    encryptedContent: string,
    nonce: string,
    otherPartyPublicKeyB64: string
  ): Promise<string> {
    if (!this.privateKey || !this.publicKey) {
      throw new Error('Private key not available');
    }

    const messageKey = await this.messageKey(otherPartyPublicKeyB64);
    return decryptMessage(encryptedContent, nonce, messageKey);
  }

  async parseMessageContent(rawContent: string, otherPartyPublicKey: string): Promise<ParsedMessage> {
    try {
      let parsed = JSON.parse(rawContent);
      if (parsed.content && typeof parsed.content === 'string' && parsed.content.trim().startsWith('{')) {
        try {
          const innerParsed = JSON.parse(parsed.content);
          if (innerParsed.encrypted) {
            parsed = innerParsed;
          } else if (innerParsed.content !== undefined) {
            parsed = innerParsed;
          }
        } catch {
        }
      }

      if (parsed.encrypted && parsed.ciphertext && parsed.nonce) {
        if (!otherPartyPublicKey) {
          return lockedMessage('[🔒 Wiadomość zaszyfrowana - brak klucza do odszyfrowania]');
        }

        if (!this.ready) {
          return lockedMessage('[🔒 Wiadomość zaszyfrowana - odblokuj E2EE aby odszyfrować]');
        }

        try {
          const decryptedPayload = await this.decrypt(parsed.ciphertext, parsed.nonce, otherPartyPublicKey);
          const decryptedData = JSON.parse(decryptedPayload);
          return {
            content: decryptedData.content || '',
            attachments: decryptedData.attachments || [],
            encrypted: true
          };
        } catch (decryptError) {
          console.error('Failed to decrypt message:', decryptError);
          return lockedMessage('[🔒 Wiadomość zaszyfrowana - nie można odszyfrować]');
        }
      }

      if (parsed.content !== undefined && typeof parsed.content === 'string' && !parsed.encrypted) {
        return {
          content: parsed.content,
          attachments: Array.isArray(parsed.attachments) ? parsed.attachments : [],
          encrypted: false
        };
      }

    } catch {
    }

    return {
      content: rawContent,
      attachments: [],
      encrypted: false
    };
  }
}
