let __hmacKeyPromise;

export function getHmacKey(te, secret) {
	if (!__hmacKeyPromise) {
		__hmacKeyPromise = crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	}
	return __hmacKeyPromise;
}
