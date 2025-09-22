export async function deriveAesKey(masterKeyB64, salt) {
	if (!masterKeyB64) throw new Error('AES_MASTER_KEY missing');
	if (!salt) throw new Error('salt missing');

	const masterBytes = Uint8Array.from(atob(masterKeyB64), (c) => c.charCodeAt(0));
	const saltBytes = typeof salt === 'string' ? Uint8Array.from(atob(salt), (c) => c.charCodeAt(0)) : salt;

	const masterKey = await crypto.subtle.importKey('raw', masterBytes, { name: 'HKDF' }, false, ['deriveKey']);

	return crypto.subtle.deriveKey(
		{ name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: new Uint8Array(0) },
		masterKey,
		{ name: 'AES-GCM', length: 256 },
		false,
		['encrypt', 'decrypt']
	);
}
