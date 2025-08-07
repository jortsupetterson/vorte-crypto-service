import { WorkerEntrypoint } from 'cloudflare:workers';

export class VorteCryptoService extends WorkerEntrypoint {
	async getCryptographicState() {
		const stateArray = new Uint8Array(16);
		crypto.getRandomValues(stateArray);
		const state = Array.from(stateArray)
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');
		return state;
	}

	async getProofKeyForCodeExchange() {
		const array = new Uint8Array(96);
		crypto.getRandomValues(array);
		const codeVerifier = btoa(String.fromCharCode(...array))
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=+$/, '');

		const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
		const base64 = btoa(String.fromCharCode(...new Uint8Array(buf)))
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=+$/, '');
		const codeChallenge = base64;

		return { codeVerifier, codeChallenge };
	}

	async get256BitKeyInBase64() {
		const raw = crypto.getRandomValues(new Uint8Array(32));
		let binary = '';
		for (let i = 0; i < raw.length; i++) {
			binary += String.fromCharCode(raw[i]);
		}
		return btoa(binary);
	}
	
}

export default {
	async fetch(request, env, ctx) {
		const cached = caches.default.match(request);
		if (cached) return cached;
		const response = new Response(null, {
			status: 404,
			headers: {
				'cache-control': 'public, max-age=31536000, immutable',
			},
		});
		ctx.waitUntil(caches.default.put(request, response.clone()));
		return response;
	},
};
