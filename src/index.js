const te = new TextEncoder();
import { WorkerEntrypoint } from 'cloudflare:workers';
import { deriveAesKey } from './deriveAesKey.js';
import { getHmacKey } from './getHmacKey.js';

export class VorteCryptoService extends WorkerEntrypoint {
	async getNonce() {
		const bytes = new Uint8Array(16);
		crypto.getRandomValues(bytes);
		let str = '';
		for (const b of bytes) {
			str += String.fromCharCode(b);
		}
		return btoa(str);
	}

	async getEightDigits() {
		const array = new Uint32Array(1);
		crypto.getRandomValues(array);
		const code = array[0] % 100_000_000;
		return code.toString().padStart(8, '0');
	}
	async getCryptographicState(seed, secret) {
		const key = await getHmacKey(te, secret);
		const msg = seed instanceof Uint8Array ? seed : te.encode(typeof seed === 'string' ? seed : String(seed));

		const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
		const out16 = mac.subarray(0, 16);
		let state = '';
		for (let i = 0; i < out16.length; i++) {
			const b = out16[i];
			state += (b >>> 4).toString(16);
			state += (b & 0x0f).toString(16);
		}
		return state;
	}

	async getProofKeyForCodeExchange() {
		const array = new Uint8Array(96);
		crypto.getRandomValues(array);
		const verifier = btoa(String.fromCharCode(...array))
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=+$/, '');

		const buf = await crypto.subtle.digest('SHA-256', te.encode(verifier));
		const challenge = btoa(String.fromCharCode(...new Uint8Array(buf)))
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=+$/, '');

		return { verifier, challenge };
	}

	async verifyProofKeyForCodeExchange(challenge, verifier) {
		const digest = await crypto.subtle.digest('SHA-256', te.encode(verifier));
		const computed = btoa(String.fromCharCode(...new Uint8Array(digest)))
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=+$/, '');
		return computed === challenge;
	}

	async get256BitKeyInBase64() {
		const raw = crypto.getRandomValues(new Uint8Array(32));
		let binary = '';
		for (let i = 0; i < raw.length; i++) {
			binary += String.fromCharCode(raw[i]);
		}
		return btoa(binary);
	}

	async encryptPayload(plainText) {
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const salt = crypto.getRandomValues(new Uint8Array(16));
		const saltB64 = btoa(String.fromCharCode(...salt));

		const masterB64 = await this.env.AES_MASTER_KEY.get();
		const aesKey = await deriveAesKey(masterB64, saltB64);

		const ptBytes = typeof plainText === 'string' ? te.encode(plainText) : plainText; // Uint8Array kelpaa
		const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, ptBytes);

		const ivB64 = btoa(String.fromCharCode(...iv));
		const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ct)));
		const saltId = btoa(`${Date.now()}${crypto.randomUUID()}`);

		this.ctx.waitUntil(this.env.CRYPTO_SALT_KV.put(saltId, saltB64));

		return `${saltId}.${ivB64}.${ctB64}`;
	}

	async decryptPayload(cipherText) {
		const [saltId, ivB64, ctB64] = cipherText.split('.');
		if (!saltId || !ivB64 || !ctB64) throw new Error(`Malformed ciphertext`);

		const saltB64 = await this.env.CRYPTO_SALT_KV.get(saltId);
		if (!saltB64) throw new Error(`Salt not found for id ${saltId}`);

		const masterB64 = await this.env.AES_MASTER_KEY.get();
		if (!masterB64) throw new Error('AES_MASTER_KEY missing');

		const [iv, ct] = [Uint8Array.from(atob(ivB64), (c) => c.charCodeAt(0)), Uint8Array.from(atob(ctB64), (c) => c.charCodeAt(0))];

		const aesKey = await deriveAesKey(masterB64, saltB64);
		const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
		const pt = new TextDecoder().decode(ptBuf);
		return {
			plainText: pt,
			saltId: saltId,
		};
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
