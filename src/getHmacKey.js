const te = new TextEncoder();
const __hmacKeyCache = new Map();

function toB64u(u8) {
	let s = '';
	for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function getHmacKey(secret) {
	const raw = secret instanceof Uint8Array ? secret : te.encode(String(secret));
	const cacheId = toB64u(raw); // turvallinen cache-avain binäärille
	let p = __hmacKeyCache.get(cacheId);
	if (!p) {
		p = crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
		__hmacKeyCache.set(cacheId, p);
	}
	return p;
}
