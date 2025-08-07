export async function handleDecryptionCall(cookie) {
	// 2) Decrypt-vaihe
	// Otetaan cookiestä key ja blob: esim key='2025-08-06:550e8400-e29b-41d4-a716-446655440000'
	const [saltKey, blob] = cookieHeader.split('=');
	const [ivB64, ctB64] = blob.split(':');

	// Hae salt KV:stä
	const saltB64 = await env.MY_SALT_KV.get(saltKey);
	const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
	const iv = Uint8Array.from(atob(ivB64), (c) => c.charCodeAt(0));
	const ct = Uint8Array.from(atob(ctB64), (c) => c.charCodeAt(0));

	// Johda avain ja decrypt
	const aesKey = await deriveAesKey(masterKey, salt);
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
}
