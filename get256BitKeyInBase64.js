export function get256BitKeyInBase64() {
	const raw = crypto.getRandomValues(new Uint8Array(32));
	let binary = '';
	for (let i = 0; i < raw.length; i++) {
		binary += String.fromCharCode(raw[i]);
	}
	return btoa(binary);
}

const base64Key = get256BitKeyInBase64();
console.log('256-bittinen avain (Base64):', base64Key);
