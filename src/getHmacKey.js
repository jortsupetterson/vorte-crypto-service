let __hmacKeyPromise;

export function getHmacKey(secret) {
	if (!__hmacKeyPromise) {
		__hmacKeyPromise = crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	}
	return __hmacKeyPromise;
}
