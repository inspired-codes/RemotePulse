// QR Scanner, WebCrypto, and Standalone Mode JS Interop Bridge for Blazor WASM
let qrScanner = null;
let scannerTimeout = null;

// Safe base64 encoder — avoids call-stack overflow on large Uint8Arrays
function _uint8ToBase64(bytes) {
  let binary = '';
  const len = bytes.byteLength;
  const chunk = 8192;
  for (let i = 0; i < len; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

window.qrScannerInterop = {
  isSecureContext: function () {
    return window.isSecureContext === true;
  },

  isLocalhost: function () {
    return ['localhost', '127.0.0.1', '::1'].includes(location.hostname);
  },

  isRunningStandalone: function () {
    if (localStorage.getItem("remotepulse_pwa_bypass") === "true") {
      return true;
    }
    return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
  },

  setBypassPwa: function () {
    localStorage.setItem("remotepulse_pwa_bypass", "true");
  },

  scrollToElement: function (elementId) {
    const el = document.getElementById(elementId);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  },

  scrollConsoleToBottom: function () {
    const el = document.querySelector(".console-output");
    if (el) el.scrollTop = el.scrollHeight;
  },

  isPageHidden: function () {
    return document.hidden === true;
  },

  // Lets the watchdog stop polling while the app is backgrounded or the screen is off. Without
  // this it keeps firing a network request every few seconds on a phone, for a screen nobody is
  // looking at - pure battery and data cost. Also fires on the way back so the UI refreshes
  // immediately on resume instead of showing stale dots until the next tick.
  registerVisibilityCallback: function (dotNetHelper) {
    if (window._rpVisibilityHandler) {
      document.removeEventListener('visibilitychange', window._rpVisibilityHandler);
    }
    window._rpVisibilityHandler = function () {
      try {
        dotNetHelper.invokeMethodAsync('OnVisibilityChanged', document.hidden === true);
      } catch (e) {
        // The component was disposed before the listener was torn down; nothing to do.
      }
    };
    document.addEventListener('visibilitychange', window._rpVisibilityHandler);
  },

  unregisterVisibilityCallback: function () {
    if (window._rpVisibilityHandler) {
      document.removeEventListener('visibilitychange', window._rpVisibilityHandler);
      window._rpVisibilityHandler = null;
    }
  },

  isOnline: function () {
    // navigator.onLine is only authoritative when false (no route at all); treat anything else
    // as "assume online and let the actual request decide".
    return navigator.onLine !== false;
  },

  // Feeds the App node of the App -> Hub -> Worker indicator and lets the watchdog skip polling
  // while there's demonstrably no connectivity (a fetch would just hang until it times out).
  registerConnectivityCallback: function (dotNetHelper) {
    if (window._rpConnHandler) {
      window.removeEventListener('online', window._rpConnHandler);
      window.removeEventListener('offline', window._rpConnHandler);
    }
    window._rpConnHandler = function () {
      try {
        dotNetHelper.invokeMethodAsync('OnConnectivityChanged', navigator.onLine !== false);
      } catch (e) {
        // Component disposed before teardown; nothing to do.
      }
    };
    window.addEventListener('online', window._rpConnHandler);
    window.addEventListener('offline', window._rpConnHandler);
  },

  unregisterConnectivityCallback: function () {
    if (window._rpConnHandler) {
      window.removeEventListener('online', window._rpConnHandler);
      window.removeEventListener('offline', window._rpConnHandler);
      window._rpConnHandler = null;
    }
  },

  startScanner: function (dotNetHelper) {
    if (!window.isSecureContext) {
      return Promise.reject("Camera access requires HTTPS or localhost.");
    }

    if (qrScanner) {
      try { qrScanner.stop(); } catch (e) {}
      qrScanner = null;
    }

    qrScanner = new Html5Qrcode("reader");
    
    return qrScanner.start(
      { facingMode: "environment" },
      {
        fps: 15,
        qrbox: (width, height) => {
          const minEdge = Math.min(width, height);
          const size = Math.floor(minEdge * 0.7);
          return { width: size, height: size };
        },
        formatsToSupport: [ Html5QrcodeSupportedFormats.QR_CODE ],
        experimentalFeatures: {
          useBarCodeDetectorIfSupported: true
        }
      },
      (decodedText, decodedResult) => {
        dotNetHelper.invokeMethodAsync("OnScanSuccess", decodedText);
      },
      (errorMessage) => { /* Ignored */ }
    ).then(() => {
      if (scannerTimeout) clearTimeout(scannerTimeout);
      scannerTimeout = setTimeout(() => {
        dotNetHelper.invokeMethodAsync("OnScannerTimeout");
        window.qrScannerInterop.stopScanner();
      }, 30000);
      return true;
    });
  },

  stopScanner: function () {
    if (scannerTimeout) {
      clearTimeout(scannerTimeout);
      scannerTimeout = null;
    }
    if (qrScanner) {
      const promise = qrScanner.stop().catch(() => {});
      qrScanner = null;
      const readerElem = document.getElementById("reader");
      if (readerElem) {
        readerElem.innerHTML = `
          <div class="scanner-placeholder" style="color: var(--text-muted); font-size: 13px; text-align: center; padding: 20px;">
            Camera scanner inactive.<br>Press "Start Scanner" to begin.
          </div>
        `;
      }
      return promise;
    }
    const readerElem = document.getElementById("reader");
    if (readerElem) {
      readerElem.innerHTML = `
        <div class="scanner-placeholder" style="color: var(--text-muted); font-size: 13px; text-align: center; padding: 20px;">
          Camera scanner inactive.<br>Press "Start Scanner" to begin.
        </div>
      `;
    }
    return Promise.resolve(true);
  },

  // Co-presence pairing link fragment (see docs/specs/pairing-v2-key-binding-spec.md). The secret deliberately
  // lives after '#' rather than in the path/query so it's never sent to any server as part of
  // the request line - only client-side JS ever sees it.
  getLocationHash: function () {
    return window.location.hash;
  },

  setTheme: function (theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("remotepulse_theme", theme);
  },

  getTheme: function () {
    const savedTheme = localStorage.getItem("remotepulse_theme");
    if (savedTheme) return savedTheme;
    return window.matchMedia('(prefers-color-scheme: light)').matches ? "light" : "dark";
  },

  // IndexedDB Key Store for Non-Extractable Private Keys and Pending Commands
  _dbPromise: null,
  getDb: function() {
    if (!this._dbPromise) {
      this._dbPromise = new Promise((resolve, reject) => {
        const req = indexedDB.open("RemotePulseStore", 2);
        req.onupgradeneeded = (e) => {
          const db = e.target.result;
          if (!db.objectStoreNames.contains("keys")) {
            db.createObjectStore("keys");
          }
          if (!db.objectStoreNames.contains("pendingCommands")) {
            db.createObjectStore("pendingCommands", { keyPath: "commandId" });
          }
        };
        req.onsuccess = (e) => {
          const db = e.target.result;
          db.onversionchange = () => {
            console.warn("IndexedDB version change requested by another tab; closing database connection.");
            db.close();
            this._dbPromise = null;
          };
          resolve(db);
        };
        req.onblocked = () => {
          console.warn("IndexedDB upgrade blocked: Please close other RemotePulse tabs to allow database upgrade.");
        };
        req.onerror = () => reject("Failed to open DB");
      });
    }
    return this._dbPromise;
  },
  saveKey: async function(keyName, cryptoKey) {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("keys", "readwrite");
      const store = tx.objectStore("keys");
      store.put(cryptoKey, keyName);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject();
    });
  },
  loadKey: async function(keyName) {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("keys", "readonly");
      const store = tx.objectStore("keys");
      const req = store.get(keyName);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject();
    });
  },

  // Checks the private key is actually present in IndexedDB - localStorage (remotepulse_app_id /
  // remotepulse_app_pub_key) and IndexedDB (the actual non-extractable CryptoKey) are two
  // separate stores that can end up out of sync (a partial storage clear, a browser storage
  // eviction, etc.), and until this check existed nothing ever verified the key was still there
  // before trusting the cached identity - the first sign attempt would fail with
  // "Private key not found in IndexedDB" instead.
  hasPrivateKey: async function () {
    try {
      const key = await this.loadKey("appPrivateKey");
      return !!key;
    } catch (e) {
      return false;
    }
  },

  // WebCrypto Helpers for Blazor WASM Cryptography
  generateAppKeys: async function () {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false, // non-extractable!
      ["sign", "verify"]
    );
    await this.saveKey("appPrivateKey", keyPair.privateKey);
    const pubSpki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    return {
      publicKeyBase64: _uint8ToBase64(new Uint8Array(pubSpki)),
      privateKeyBase64: "" // Omitted since it's non-extractable
    };
  },

  signMessage: async function (privateKeyBase64_ignored, messageText) {
    const privateKey = await this.loadKey("appPrivateKey");
    if (!privateKey) throw new Error("Private key not found in IndexedDB");
    const messageBytes = new TextEncoder().encode(messageText);
    const signature = await window.crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      messageBytes
    );
    return _uint8ToBase64(new Uint8Array(signature));
  },

  hybridEncryptPayload: async function (jsonText, recipientPublicKeyBase64) {
    // 1. Generate ephemeral ECDH P-256 key pair
    const ephemeralKeyPair = await window.crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );

    // 2. Import recipient's static public key (SPKI format)
    const pubBytes = Uint8Array.from(atob(recipientPublicKeyBase64), c => c.charCodeAt(0));
    const recipientPublicKey = await window.crypto.subtle.importKey(
      "spki",
      pubBytes,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    // 3. Derive shared secret bits
    const sharedSecret = await window.crypto.subtle.deriveBits(
      { name: "ECDH", public: recipientPublicKey },
      ephemeralKeyPair.privateKey,
      256
    );

    // 4. HKDF to derive AES-256-GCM key
    const hkdfKey = await window.crypto.subtle.importKey(
      "raw",
      sharedSecret,
      "HKDF",
      false,
      ["deriveKey"]
    );
    
    // We need the raw uncompressed 65-byte ephemeral public key for the HKDF salt and wire format
    const ephemeralPubSpki = await window.crypto.subtle.exportKey("spki", ephemeralKeyPair.publicKey);
    const ephemeralPubBytes = new Uint8Array(ephemeralPubSpki);
    // In SPKI for P-256, the last 65 bytes are the uncompressed point (0x04 || X || Y)
    const rawEphemeralKey = ephemeralPubBytes.slice(-65);

    const aesKey = await window.crypto.subtle.deriveKey(
      {
        // Must match InspiredCodes.RemotePulse.Shared.Cryptography.HybridCrypto exactly:
        // HKDF-SHA256, empty salt, info = "RemotePulse-v3" (HybridCrypto.HkdfInfo) - both sides
        // derive the same 32-byte AES-GCM key from the same ECDH shared secret this way.
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: new TextEncoder().encode("RemotePulse-v3")
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    // 5. AES-GCM Encrypt (SEC-9: rawEphemeralKey bound into AEAD additionalData)
    const nonce = window.crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(jsonText);
    const encryptedContent = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: rawEphemeralKey, tagLength: 128 },
      aesKey,
      plaintext
    );

    const contentBytes = new Uint8Array(encryptedContent);
    const ciphertextLen = contentBytes.byteLength - 16;
    const ciphertextBytes = contentBytes.subarray(0, ciphertextLen);
    const tagBytes = contentBytes.subarray(ciphertextLen);

    // 6. Assemble wire format
    const totalLen = 65 + 12 + 16 + ciphertextLen;
    const result = new Uint8Array(totalLen);
    let offset = 0;

    result.set(rawEphemeralKey, offset);
    offset += 65;

    result.set(nonce, offset);
    offset += 12;

    result.set(tagBytes, offset);
    offset += 16;

    result.set(ciphertextBytes, offset);

    return _uint8ToBase64(result);
  },

  // E2E Command Results Reply Key Generation & Decryption
  generateReplyKey: async function (commandId, machineId, timeoutSeconds) {
    // 1. Generate 256-bit AES-GCM key (extractable initially so we can read raw bytes once)
    const key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    // 2. Export raw bytes for envelope packaging
    const rawBytes = await window.crypto.subtle.exportKey("raw", key);
    const replyKeyBase64 = _uint8ToBase64(new Uint8Array(rawBytes));

    // 3. Re-import as non-extractable CryptoKey for local decryption only
    const nonExtractableKey = await window.crypto.subtle.importKey(
      "raw",
      rawBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    // 4. Save into pendingCommands IndexedDB object store
    const db = await this.getDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction("pendingCommands", "readwrite");
      const store = tx.objectStore("pendingCommands");
      const record = {
        commandId: commandId,
        machineId: machineId || "",
        key: nonExtractableKey,
        sentAtUtc: new Date().toISOString(),
        timeoutSeconds: timeoutSeconds || 90
      };
      store.put(record);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error("Failed to store pending command key in IndexedDB"));
    });

    return replyKeyBase64;
  },

  decryptResult: async function (commandId, encryptedBlobBase64) {
    const db = await this.getDb();
    // 1. Retrieve non-extractable CryptoKey from pendingCommands
    const record = await new Promise((resolve, reject) => {
      const tx = db.transaction("pendingCommands", "readonly");
      const store = tx.objectStore("pendingCommands");
      const req = store.get(commandId);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(new Error("Failed to read pending command from IndexedDB"));
    });

    if (!record || !record.key) {
      throw new Error("No decryption key found in IndexedDB for command " + commandId);
    }

    // 2. Decode wire format: Nonce (12 bytes) || Ciphertext || Tag (16 bytes)
    const blobBytes = Uint8Array.from(atob(encryptedBlobBase64), c => c.charCodeAt(0));
    if (blobBytes.byteLength < 12 + 16) {
      throw new Error("Encrypted payload is too short.");
    }

    const nonce = blobBytes.subarray(0, 12);
    const ciphertextAndTag = blobBytes.subarray(12);
    const aad = new TextEncoder().encode(commandId);

    // 3. WebCrypto AES-GCM Decrypt
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: aad,
        tagLength: 128
      },
      record.key,
      ciphertextAndTag
    );

    // 4. Clean up key from IndexedDB after successful decryption
    try {
      await this.removePendingCommand(commandId);
    } catch (e) {
      // Non-fatal if cleanup fails
    }

    return new TextDecoder().decode(decryptedBuffer);
  },

  getPendingCommands: async function () {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("pendingCommands", "readonly");
      const store = tx.objectStore("pendingCommands");
      const req = store.getAll();
      req.onsuccess = () => {
        const list = (req.result || []).map(r => ({
          commandId: r.commandId,
          machineId: r.machineId,
          sentAtUtc: r.sentAtUtc,
          timeoutSeconds: r.timeoutSeconds
        }));
        resolve(list);
      };
      req.onerror = () => reject(new Error("Failed to load pending commands from IndexedDB"));
    });
  },

  removePendingCommand: async function (commandId) {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("pendingCommands", "readwrite");
      const store = tx.objectStore("pendingCommands");
      store.delete(commandId);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(new Error("Failed to remove pending command from IndexedDB"));
    });
  }
};
