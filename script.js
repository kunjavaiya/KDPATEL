let rsaKeyPair, aesKey, iv;

function toggleTheme() {
  document.body.classList.toggle("light-theme");
}

async function generateRSAKeys() {
  rsaKeyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );

  const publicKeyJwk = await crypto.subtle.exportKey("jwk", rsaKeyPair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", rsaKeyPair.privateKey);

  document.getElementById("publicKey").value = JSON.stringify(publicKeyJwk, null, 2);
  document.getElementById("privateKey").value = JSON.stringify(privateKeyJwk, null, 2);
}

async function encryptMessage() {
  const message = document.getElementById("message").value;
  iv = crypto.getRandomValues(new Uint8Array(12));

  aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const encoded = new TextEncoder().encode(message);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encoded
  );

  const publicKeyJwk = JSON.parse(document.getElementById("publicKey").value);
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    publicKeyJwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );

  const rawAES = await crypto.subtle.exportKey("raw", aesKey);
  const encryptedAESKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    rawAES
  );

  document.getElementById("encryptedMessage").value = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
  document.getElementById("encryptedAESKey").value = btoa(String.fromCharCode(...new Uint8Array(encryptedAESKey)));
}

async function decryptMessage() {
  const encryptedAESKeyB64 = document.getElementById("encryptedAESKey").value;
  const encryptedMessageB64 = document.getElementById("encryptedMessage").value;
  const privateKeyJwk = JSON.parse(document.getElementById("privateKey").value);

  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateKeyJwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );

  const encryptedAESKey = Uint8Array.from(atob(encryptedAESKeyB64), c => c.charCodeAt(0));
  const rawAESKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encryptedAESKey
  );

  const decryptedAESKey = await crypto.subtle.importKey(
    "raw",
    rawAESKey,
    { name: "AES-GCM" },
    true,
    ["decrypt"]
  );

  const ciphertext = Uint8Array.from(atob(encryptedMessageB64), c => c.charCodeAt(0));
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    decryptedAESKey,
    ciphertext
  );

  const decoded = new TextDecoder().decode(decrypted);
  document.getElementById("decryptedMessage").value = decoded;
}
