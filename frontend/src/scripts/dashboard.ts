import { API_URL, getToken, getEmail, requireLogin, fetchCSRFToken } from '../lib/api';
import { base64ToArrayBuffer, importPublicKey, deriveSharedSecret, deriveMessageKey, encryptMessage, decryptMessage } from '../lib/crypto';

    declare const marked: { parse: (text: string, options?: { async?: boolean }) => string | Promise<string> };
    declare const DOMPurify: { sanitize: (html: string, config?: object) => string };

    let currentFiles: File[] = [];
    let currentTab = 'inbox';
    let csrfToken = '';

    let myPublicKey: string | null = null;
    let myPrivateKey: CryptoKey | null = null;
    let e2eeReady = false;
    let myFingerprint: string | null = null;
    let totalPages = 1;

    function renderMarkdown(content: string): string {
      try {
        if (typeof marked === 'undefined') {
          console.error('marked library not loaded');
          return escapeHtml(content);
        }
        if (typeof DOMPurify === 'undefined') {
          console.error('DOMPurify library not loaded');
          return escapeHtml(content);
        }
        let rawHtml: string;
        try {
          rawHtml = marked.parse(content, { async: false }) as string;
        } catch (parseError) {
          console.error('Markdown parse error:', parseError);
          return escapeHtml(content);
        }

        const cleanHtml = DOMPurify.sanitize(rawHtml, {
          ALLOWED_TAGS: [
            'p', 'br', 'strong', 'em', 'b', 'i', 'u', 's', 'strike', 'del',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
            'a', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
            'sup', 'sub'
          ],
          ALLOWED_ATTR: ['href', 'title'],
          FORBID_TAGS: [
            'script', 'style', 'iframe', 'frame', 'frameset',
            'form', 'input', 'button', 'select', 'textarea',
            'object', 'embed', 'applet', 'link', 'meta', 'base',
            'svg', 'math', 'template', 'noscript', 'canvas', 'audio', 'video'
          ],
          FORBID_ATTR: [
            'onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout',
            'onmousedown', 'onmouseup', 'onfocus', 'onblur', 'onchange',
            'onsubmit', 'onreset', 'onkeydown', 'onkeyup', 'onkeypress',
            'style', 'class', 'id', 'name', 'action', 'formaction',
            'src', 'srcdoc', 'data', 'dynsrc', 'lowsrc', 'background',
            'poster', 'codebase', 'cite', 'xlink:href', 'xml:base'
          ],
          ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto):|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
          KEEP_CONTENT: false,
          DATA_URI_TAGS: [],
          USE_PROFILES: { html: true }
        });

        const secureHtml = cleanHtml.replace(
          /<a\s+href="([^"]+)"([^>]*)>/gi,
          (match, href, rest) => {
            if (!/^(https?:|mailto:)/i.test(href)) {
              return '<span>';
            }
            return `<a href="${href}" target="_blank" rel="noopener noreferrer nofollow"${rest}>`;
          }
        );

        return secureHtml;
      } catch (error) {
        console.error('Markdown rendering error:', error);
        return escapeHtml(content);
      }
    }

    function escapeHtml(text: string): string {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    requireLogin();
    const token = getToken();
    const userEmail = getEmail();

    document.getElementById('userEmail')!.textContent = userEmail;

    let e2eePepper: string = '';

    async function fetchE2EEConfig(): Promise<void> {
      try {
        const response = await fetch('/api/e2ee/config', {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.ok) {
          const config = await response.json();
          e2eePepper = config.pepper || '';
        }
      } catch (error) {
        console.error('Failed to fetch E2EE config:', error);
      }
    }

    async function getReceiverPublicKey(receiverEmail: string): Promise<string | null> {
      try {
        const response = await fetch(`${API_URL}/api/user/public-key?email=${encodeURIComponent(receiverEmail)}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.ok) {
          const data = await response.json();
          return data.e2ee_public_key || null;
        }
      } catch (error) {
        console.error('Failed to get receiver public key:', error);
      }
      return null;
    }

      async function e2eeEncryptMessage(content: string, receiverPublicKeyB64: string): Promise<{
      encryptedContent: string,
      nonce: string,
      senderPublicKey: string
    }> {
      if (!myPrivateKey || !myPublicKey) {
        throw new Error('Sender keys not available');
      }

      const receiverPublicKey = await importPublicKey(receiverPublicKeyB64);

      const sharedSecret = await deriveSharedSecret(myPrivateKey, receiverPublicKey);
      const sortedKeys = [myPublicKey, receiverPublicKeyB64].sort().join('');
      const saltData = new TextEncoder().encode(sortedKeys);
      const saltHash = await crypto.subtle.digest('SHA-256', saltData);

      const messageKey = await deriveMessageKey(sharedSecret, 'message-encryption', saltHash, e2eePepper);

      const { ciphertext, nonce } = await encryptMessage(content, messageKey);

      return {
        encryptedContent: ciphertext,
        nonce: nonce,
        senderPublicKey: myPublicKey
      };
    }

    async function e2eeDecryptMessage(
      encryptedContent: string,
      nonce: string,
      otherPartyPublicKeyB64: string
    ): Promise<string> {
      if (!myPrivateKey || !myPublicKey) {
        throw new Error('Private key not available');
      }

      const otherPartyPublicKey = await importPublicKey(otherPartyPublicKeyB64);
      const sharedSecret = await deriveSharedSecret(myPrivateKey, otherPartyPublicKey);
      const sortedKeys = [myPublicKey, otherPartyPublicKeyB64].sort().join('');
      const saltData = new TextEncoder().encode(sortedKeys);
      const saltHash = await crypto.subtle.digest('SHA-256', saltData);

      const messageKey = await deriveMessageKey(sharedSecret, 'message-encryption', saltHash, e2eePepper);
      return decryptMessage(encryptedContent, nonce, messageKey);
    }

    async function initializeE2EE() {
      await fetchE2EEConfig();

      myPublicKey = localStorage.getItem('e2ee_public_key');
      const privateKeyB64 = sessionStorage.getItem('e2ee_private_key_pkcs8');

      if (myPublicKey && privateKeyB64) {
        try {
          const privateKeyPkcs8 = base64ToArrayBuffer(privateKeyB64);
          myPrivateKey = await crypto.subtle.importKey(
            'pkcs8',
            privateKeyPkcs8,
            { name: 'X25519' },
            false,
            ['deriveBits']
          );

          e2eeReady = true;
          console.log('E2EE initialized successfully');
        } catch (error) {
          console.error('Failed to initialize E2EE:', error);
          e2eeReady = false;
        }
      } else {
        console.warn('E2EE keys not available - please re-login to enable encryption');
        if (!myPublicKey) console.warn('Missing: e2ee_public_key');
        if (!privateKeyB64) console.warn('Missing: e2ee_private_key_pkcs8 (session) - re-login required');
        e2eeReady = false;
      }
    }

    async function parseMessageContent(rawContent: string, otherPartyPublicKey: string): Promise<{ content: string, attachments: any[], encrypted: boolean }> {
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
            return {
              content: '[🔒 Wiadomość zaszyfrowana - brak klucza do odszyfrowania]',
              attachments: [],
              encrypted: true
            };
          }

          if (!e2eeReady) {
            return {
              content: '[🔒 Wiadomość zaszyfrowana - odblokuj E2EE aby odszyfrować]',
              attachments: [],
              encrypted: true
            };
          }

          try {
            const decryptedPayload = await e2eeDecryptMessage(parsed.ciphertext, parsed.nonce, otherPartyPublicKey);
            const decryptedData = JSON.parse(decryptedPayload);
            return {
              content: decryptedData.content || '',
              attachments: decryptedData.attachments || [],
              encrypted: true
            };
          } catch (decryptError) {
            console.error('Failed to decrypt message:', decryptError);
            return {
              content: '[🔒 Wiadomość zaszyfrowana - nie można odszyfrować]',
              attachments: [],
              encrypted: true
            };
          }
        }

        if (parsed.content !== undefined && typeof parsed.content === 'string' && !parsed.encrypted) {
          return {
            content: parsed.content,
            attachments: Array.isArray(parsed.attachments) ? parsed.attachments : [],
            encrypted: false
          };
        }

        return {
          content: rawContent,
          attachments: [],
          encrypted: false
        };
      } catch (e) {
        return {
          content: rawContent,
          attachments: [],
          encrypted: false
        };
      }
    }

    document.getElementById('logoutBtn')!.addEventListener('click', () => {
      localStorage.removeItem('jwt_token');
      localStorage.removeItem('user_email');
      localStorage.removeItem('user_id');
      localStorage.removeItem('e2ee_public_key');
      sessionStorage.removeItem('e2ee_private_key_pkcs8');
      window.location.href = '/login';
    });

    async function getCsrfToken() {
      csrfToken = await fetchCSRFToken();
    }

    const fileUpload = document.getElementById('fileUpload')!;
    const fileInput = document.getElementById('fileInput')! as HTMLInputElement;
    const fileList = document.getElementById('fileList')!;
    fileUpload.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
      const files = Array.from((e.target as HTMLInputElement).files || []);
      addFiles(files);
    });
    fileUpload.addEventListener('dragover', (e) => {
      e.preventDefault();
      fileUpload.classList.add('dragover');
    });
    fileUpload.addEventListener('dragleave', () => {
      fileUpload.classList.remove('dragover');
    });
    fileUpload.addEventListener('drop', (e) => {
      e.preventDefault();
      fileUpload.classList.remove('dragover');
      const files = Array.from(e.dataTransfer?.files || []);
      addFiles(files);
    });

    function addFiles(files: File[]) {
      for (const file of files) {
        if (file.size > 15 * 1024 * 1024) {
          alert(`File ${file.name} is too large (max 15MB)`);
          continue;
        }
        currentFiles.push(file);
      }
      renderFileList();
    }

    function renderFileList() {
      fileList.innerHTML = '';
      currentFiles.forEach((file, index) => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        fileItem.innerHTML = `
          <div class="file-item-info">
            <span class="file-icon">📄</span>
            <span>${escapeHtml(file.name)}</span>
            <span class="file-size">(${escapeHtml(formatFileSize(file.size))})</span>
          </div>
          <button type="button" class="remove-file" data-index="${index}">Remove</button>
        `;
        fileList.appendChild(fileItem);
      });

      document.querySelectorAll('.remove-file').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const index = parseInt((e.target as HTMLElement).dataset.index || '0');
          currentFiles.splice(index, 1);
          renderFileList();
        });
      });
    }

    function formatFileSize(bytes: number): string {
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    document.getElementById('composeForm')!.addEventListener('submit', async (e) => {
      e.preventDefault();

      const receiverEmail = (document.getElementById('receiverEmail')! as HTMLInputElement).value;
      const messageContent = (document.getElementById('messageContent')! as HTMLTextAreaElement).value;
      const sendBtn = document.getElementById('sendBtn')! as HTMLButtonElement;

      sendBtn.disabled = true;
      sendBtn.textContent = 'Encrypting & Sending...';

      try {
        const attachments = await Promise.all(currentFiles.map(async (file) => {
          return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => {
              const base64 = (reader.result as string).split(',')[1];
              resolve({
                filename: file.name,
                content_type: file.type || 'application/octet-stream',
                size: file.size,
                data: base64
              });
            };
            reader.onerror = reject;
            reader.readAsDataURL(file);
          });
        }));

        const messagePayload = JSON.stringify({
          content: messageContent,
          attachments: attachments
        });

        let finalContent = messagePayload;
        let senderPublicKey = '';
        let receiverPublicKeyForMsg = '';
        let encrypted = false;

        if (e2eeReady) {
          try {
            const receiverPublicKey = await getReceiverPublicKey(receiverEmail);

            if (receiverPublicKey) {
              const encryptedData = await e2eeEncryptMessage(messagePayload, receiverPublicKey);
              finalContent = JSON.stringify({
                encrypted: true,
                ciphertext: encryptedData.encryptedContent,
                nonce: encryptedData.nonce
              });

              senderPublicKey = encryptedData.senderPublicKey;
              receiverPublicKeyForMsg = receiverPublicKey;
              encrypted = true;
              console.log('Message encrypted with E2EE (shared secret)');
            } else {
              console.warn('Receiver does not have E2EE keys, sending unencrypted');
            }
          } catch (encryptError) {
            console.error('E2EE encryption failed, sending unencrypted:', encryptError);
          }
        }

        console.log('Sending message with', attachments.length, 'attachments, encrypted:', encrypted);

        const response = await fetch(`${API_URL}/api/messages/send`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            receiver_email: receiverEmail,
            content: finalContent,
            csrf_token: csrfToken,
            dh_public_key: senderPublicKey,
            receiver_public_key: receiverPublicKeyForMsg
          })
        });

        if (response.ok) {
          alert('Message sent successfully!' + (encrypted ? ' (End-to-End Encrypted)' : ''));
          (document.getElementById('composeForm')! as HTMLFormElement).reset();
          currentFiles = [];
          renderFileList();
          loadMessages();
        } else {
          let errorMessage = `Failed to send message (${response.status})`;
          const contentType = response.headers.get('content-type') || '';
          if (contentType.includes('application/json')) {
            try {
              const error = await response.json();
              errorMessage = `Failed to send message: ${error.message}`;
            } catch (e) {
            }
          }
          console.error('Send error:', response.status);
          alert(errorMessage);
        }
      } catch (error) {
        console.error('Send error:', error);
        if (error instanceof TypeError && error.message.includes('fetch')) {
          alert('Network error: Unable to reach server. Please check your connection.');
        } else {
          alert(`Network error: ${error.message || 'Please try again.'}`);
        }
      } finally {
        sendBtn.disabled = false;
        sendBtn.textContent = 'Send Message 🚀';
      }
    });

    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', (e) => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        (e.target as HTMLElement).classList.add('active');
        currentTab = (e.target as HTMLElement).dataset.tab || 'inbox';
        loadMessages();
      });
    });

    async function loadMessages(page = 1) {
      const container = document.getElementById('messageContainer')!;
      container.innerHTML = '<div class="loading">Loading messages...</div>';

      const endpoint = currentTab === 'inbox' ? '/api/messages' : '/api/messages/sent';

      try {
        const response = await fetch(`${API_URL}${endpoint}?page=${page}&limit=20`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) throw new Error('Failed to load messages');

        const data = await response.json();
        const messages = data.messages || data;
        const pagination = data.pagination;

        if (pagination) {
          totalPages = pagination.total_pages;
        }

        if (messages.length === 0) {
          container.innerHTML = '<div class="loading">No messages</div>';
          return;
        }

        const messageList = document.createElement('div');
        messageList.className = 'message-list';

        for (const msg of messages) {
          messageList.appendChild(await buildMessageItem(msg));
        }

        container.innerHTML = '';
        container.appendChild(messageList);

        if (pagination && totalPages > 1) {
          container.appendChild(buildPaginationNav(page));
        }
      } catch (error) {
        console.error('Load messages error:', error);
        container.innerHTML = '<div class="error">Failed to load messages</div>';
      }
    }

    async function buildMessageItem(msg: any): Promise<HTMLElement> {
      const messageItem = document.createElement('div');
      messageItem.className = `message-item ${!msg.is_read && currentTab === 'inbox' ? 'unread' : ''}`;
      messageItem.setAttribute('data-message-id', msg.id);

      const fromEmail = currentTab === 'inbox' ? msg.sender_email : msg.receiver_email;

      let preview = '[Encrypted message]';
      let isEncrypted = false;
      try {
        const keyForDecryption = currentTab === 'inbox'
          ? (msg.dh_public_key || '')
          : (msg.receiver_public_key || '');
        const parsed = await parseMessageContent(msg.content, keyForDecryption);
        preview = parsed.content.length > 100 ? parsed.content.substring(0, 100) + '...' : parsed.content;
        isEncrypted = parsed.encrypted;
      } catch (e) {
        preview = msg.content.length > 100 ? msg.content.substring(0, 100) + '...' : msg.content;
      }

      messageItem.innerHTML = `
        <div class="message-header">
          <span class="message-from">${escapeHtml(currentTab === 'inbox' ? 'From' : 'To')}: ${escapeHtml(fromEmail)} ${isEncrypted ? '🔒' : ''}</span>
          <span class="message-date">${escapeHtml(new Date(msg.created_at).toLocaleString())}</span>
        </div>
        <div class="message-preview">${escapeHtml(preview)}</div>
      `;

      messageItem.addEventListener('click', () => openMessage(msg.id));
      return messageItem;
    }

    function buildPaginationNav(page: number): HTMLElement {
      const nav = document.createElement('div');
      nav.style.cssText = 'display: flex; justify-content: center; align-items: center; gap: 10px; margin-top: 20px; padding: 15px;';

      const prevBtn = document.createElement('button');
      prevBtn.textContent = '← Previous';
      prevBtn.disabled = page <= 1;
      prevBtn.addEventListener('click', () => loadMessages(page - 1));

      const pageInfo = document.createElement('span');
      pageInfo.textContent = `Page ${page} of ${totalPages}`;
      pageInfo.style.cssText = 'font-size: 14px; color: #666;';

      const nextBtn = document.createElement('button');
      nextBtn.textContent = 'Next →';
      nextBtn.disabled = page >= totalPages;
      nextBtn.addEventListener('click', () => loadMessages(page + 1));

      nav.appendChild(prevBtn);
      nav.appendChild(pageInfo);
      nav.appendChild(nextBtn);
      return nav;
    }

    async function openMessage(messageId: number) {
      const modal = document.getElementById('messageModal')!;
      const detail = document.getElementById('messageDetail')!;

      modal.classList.add('active');
      detail.innerHTML = '<div class="loading">Decrypting message...</div>';

      try {
        const response = await fetch(`${API_URL}/api/messages/get?id=${messageId}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) throw new Error('Failed to load message');

        const msg = await response.json();

        if (currentTab === 'inbox' && !msg.is_read) {
          markMessageAsRead(messageId);
        }

        const keyForDecryption = currentTab === 'inbox'
          ? (msg.dh_public_key || '')
          : (msg.receiver_public_key || '');

        const parsedContent = await parseMessageContent(msg.content, keyForDecryption);
        console.log('Parsed content:', {
          content: parsedContent.content?.substring(0, 50),
          attachmentsCount: parsedContent.attachments?.length,
          attachments: parsedContent.attachments?.map((a: any) => ({ filename: a.filename, hasData: !!a.data })),
          encrypted: parsedContent.encrypted
        });
        const messageContent = parsedContent.content;
        const attachments = parsedContent.attachments;
        const isEncrypted = parsedContent.encrypted;

        (window as any).currentMessageAttachments = attachments;

        let attachmentsHtml = '';
        if (attachments && attachments.length > 0) {
          attachmentsHtml = '<h4>Attachments:</h4><div class="attachment-list">';
          attachments.forEach((att: any, index: number) => {
            attachmentsHtml += `
              <div class="attachment-item">
                <div>
                  <span class="file-icon">📄</span>
                  <strong>${escapeHtml(att.filename)}</strong>
                  <span class="file-size">(${escapeHtml(formatFileSize(att.size))})</span>
                </div>
                <button class="download-btn" onclick="downloadAttachmentByIndex(${index})">
                  Download
                </button>
              </div>
            `;
          });
          attachmentsHtml += '</div>';
        }

        detail.innerHTML = `
          <div class="message-full">
            <div class="from">${escapeHtml(currentTab === 'inbox' ? 'From' : 'To')}: ${escapeHtml(currentTab === 'inbox' ? msg.sender_email : msg.receiver_email)} ${isEncrypted ? '<span style="color: #28a745;">🔒 End-to-End Encrypted</span>' : ''}</div>
            <div class="date">${escapeHtml(new Date(msg.created_at).toLocaleString())}</div>
            <div class="content"></div>
            ${attachmentsHtml}
            <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid #eee;">
              <button class="download-btn" style="background: #dc3545;" onclick="deleteMessage(${msg.id})">
                🗑️ Delete Message
              </button>
            </div>
          </div>
        `;

        const contentDiv = detail.querySelector('.content');
        if (contentDiv) {
          contentDiv.innerHTML = renderMarkdown(messageContent);
        }
      } catch (error) {
        console.error('Open message error:', error);
        detail.innerHTML = '<div class="error">Failed to load message</div>';
      }
    }

    (window as any).downloadAttachmentByIndex = function(index: number) {
      try {
        const attachments = (window as any).currentMessageAttachments;
        if (!attachments || !attachments[index]) {
          alert('Attachment not found');
          return;
        }

        const att = attachments[index];
        const binaryString = atob(att.data);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }

        const blob = new Blob([bytes], { type: att.content_type });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = att.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } catch (error) {
        console.error('Download error:', error);
        alert('Failed to download attachment');
      }
    };

    (window as any).deleteMessage = async function(messageId: number) {
      if (!confirm('Are you sure you want to delete this message?')) return;

      try {
        const response = await fetch(`${API_URL}/api/messages/delete`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ message_id: messageId })
        });

        if (response.ok) {
          document.getElementById('messageModal')!.classList.remove('active');
          loadMessages();
          alert('Message deleted successfully');
        } else {
          const error = await response.json();
          alert(`Failed to delete message: ${error.message}`);
        }
      } catch (error) {
        console.error('Delete error:', error);
        alert('Failed to delete message');
      }
    };

    async function markMessageAsRead(messageId: number) {
      try {
        const response = await fetch(`${API_URL}/api/messages/mark-read`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ message_id: messageId })
        });

        if (response.ok) {
          const messageItem = document.querySelector(`[data-message-id="${messageId}"]`);
          if (messageItem) {
            messageItem.classList.remove('unread');
          }
        }
      } catch (error) {
        console.error('Error marking message as read:', error);
      }
    }

    document.getElementById('closeModal')!.addEventListener('click', () => {
      document.getElementById('messageModal')!.classList.remove('active');
    });

    document.getElementById('messageModal')!.addEventListener('click', (e) => {
      if (e.target === e.currentTarget) {
        (e.target as HTMLElement).classList.remove('active');
      }
    });

    async function fetchFingerprint() {
      try {
        const response = await fetch(`${API_URL}/api/e2ee/fingerprint`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (response.ok) {
          const data = await response.json();
          myFingerprint = data.fingerprint;
          const display = document.getElementById('fingerprintDisplay');
          if (display && myFingerprint) {
            display.textContent = '🔑 ' + myFingerprint.substring(0, 16) + '...';
            display.title = 'Your E2EE fingerprint:\n' + myFingerprint.match(/.{1,4}/g)?.join(' ') + '\n\nShare this with others to verify your identity.';
          }
        }
      } catch (error) {
        console.error('Failed to fetch fingerprint:', error);
      }
    }

    document.getElementById('fingerprintDisplay')?.addEventListener('click', () => {
      if (myFingerprint) {
        const formatted = myFingerprint.match(/.{1,4}/g)?.join(' ') || myFingerprint;
        alert('Your E2EE Key Fingerprint:\n\n' + formatted + '\n\nShare this with others to verify your identity.');
      }
    });

    document.getElementById('verifyFingerprintBtn')?.addEventListener('click', async () => {
      const email = (document.getElementById('receiverEmail') as HTMLInputElement).value;
      if (!email) {
        alert('Please enter a recipient email first');
        return;
      }
      try {
        const response = await fetch(`${API_URL}/api/user/fingerprint?email=${encodeURIComponent(email)}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const info = document.getElementById('recipientFingerprintInfo')!;
        if (response.ok) {
          const data = await response.json();
          const formatted = data.fingerprint.match(/.{1,4}/g)?.join(' ') || data.fingerprint;
          info.innerHTML = `🔒 Recipient's fingerprint: <code style="background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 11px;">${formatted}</code>`;
          info.style.display = 'block';
        } else {
          info.textContent = '⚠️ Could not fetch fingerprint - user may not have E2EE configured';
          info.style.display = 'block';
        }
      } catch (error) {
        console.error('Fingerprint lookup error:', error);
      }
    });

    async function initialize() {
      await initializeE2EE();
      await fetchFingerprint();
      await getCsrfToken();
      await loadMessages();
      if (e2eeReady) {
        console.log('✅ E2EE is active - messages will be encrypted');
      } else {
        console.warn('⚠️ E2EE not available - please re-login to enable encryption');
      }
    }

    initialize();
