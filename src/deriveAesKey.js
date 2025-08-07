

export async function deriveAesKey(masterKeyRawB64, saltRawB64) {
  // dekoodaa base64→Uint8Array
  const masterBytes = Uint8Array.from(atob(masterKeyRawB64), c => c.charCodeAt(0));
  const saltBytes   = Uint8Array.from(atob(saltRawB64),   c => c.charCodeAt(0));

  // tuo masterKey HMAC-pohjaiseksi KDF:lähteeksi
  const masterKey = await crypto.subtle.importKey(
    'raw', masterBytes,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  // johda AES-GCM-256-avain
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltBytes
    },
    masterKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );

  return aesKey;
}
