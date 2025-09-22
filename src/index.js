let __aesMasterKeyCache;

const te = new TextEncoder();
const td = new TextDecoder();

const MOD = 100_000_000;
const LIMIT = 0x1_0000_0000 - (0x1_0000_0000 % MOD);

import { WorkerEntrypoint } from 'cloudflare:workers';
import { deriveAesKey } from './deriveAesKey.js';
import { getHmacKey } from './getHmacKey.js';

export class VorteCryptoService extends WorkerEntrypoint {
	async getNonce() {
		const bytes = new Uint8Array(16);
		crypto.getRandomValues(bytes);
		let s = '';
		for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
		return btoa(s);
	}

	async getEightDigits() {
		const buf = new Uint32Array(1);
		// bias-free rejection sampling
		// odotusarvo ~1.023 arvontaa
		for (;;) {
			crypto.getRandomValues(buf);
			const x = buf[0];
			if (x < LIMIT) {
				const n = x % MOD;
				return n.toString().padStart(8, '0');
			}
		}
	}

	async getHashBasedMessageAuthenticationCode(seed, secret, bytes = 16, namespace = '') {
		// clampataan bytes välille 1..32 (HMAC-SHA256 tuottaa 32 tavua)
		bytes = Math.min(32, Math.max(1, bytes | 0));

		const key = await getHmacKey(secret);

		let msg = seed instanceof Uint8Array ? seed : te.encode(String(seed));
		if (namespace && namespace.length) {
			// kevyt domain-separaatio ilman ylikikkailua
			const ns = te.encode(namespace + '\x1c');
			const merged = new Uint8Array(ns.length + msg.length);
			merged.set(ns, 0);
			merged.set(msg, ns.length);
			msg = merged;
		}

		const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
		const out = mac.subarray(0, bytes);

		// heksaus: nopea ja selkeä
		let hex = '';
		for (let i = 0; i < out.length; i++) {
			hex += out[i].toString(16).padStart(2, '0');
		}
		return hex;
	}

	async getProofKeyForCodeExchange() {
		const array = new Uint8Array(96);
		crypto.getRandomValues(array);
		// base64url ilman riippuvuuksia
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
		let s = '';
		for (let i = 0; i < raw.length; i++) s += String.fromCharCode(raw[i]);
		return btoa(s);
	}

	async encryptPayload(plainText) {
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const salt = crypto.getRandomValues(new Uint8Array(16));
		const saltB64 = btoa(String.fromCharCode(...salt));

		if (!__aesMasterKeyCache) {
			__aesMasterKeyCache = await this.env.AES_MASTER_KEY.get();
		}
		const masterB64 = __aesMasterKeyCache;
		const aesKey = await deriveAesKey(masterB64, saltB64);

		const ptBytes = typeof plainText === 'string' ? te.encode(plainText) : plainText;
		const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, ptBytes);

		const ivB64 = btoa(String.fromCharCode(...iv));
		const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ct)));
		const saltId = btoa(`${Date.now()}${crypto.randomUUID()}`);

		this.ctx.waitUntil(this.env.CRYPTO_SALT_KV.put(saltId, saltB64));
		return `${saltId}.${ivB64}.${ctB64}`;
	}

	async decryptPayload(cipherText) {
		const [saltId, ivB64, ctB64] = cipherText.split('.');
		if (!saltId || !ivB64 || !ctB64) throw new Error('Malformed ciphertext');

		const saltB64 = await this.env.CRYPTO_SALT_KV.get(saltId);
		if (!saltB64) throw new Error(`Salt not found for id ${saltId}`);

		if (!__aesMasterKeyCache) {
			__aesMasterKeyCache = await this.env.AES_MASTER_KEY.get();
		}
		const masterB64 = __aesMasterKeyCache;
		if (!masterB64) throw new Error('AES_MASTER_KEY missing');

		const iv = Uint8Array.from(atob(ivB64), (c) => c.charCodeAt(0));
		const ct = Uint8Array.from(atob(ctB64), (c) => c.charCodeAt(0));

		const aesKey = await deriveAesKey(masterB64, saltB64);
		const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
		const pt = td.decode(ptBuf);

		return { plainText: pt, saltId };
	}
}

export default {
	async fetch(request, env, ctx) {
		const cached = await caches.default.match(request);
		if (cached) return cached;
		const response = new Response(null, {
			status: 404,
			headers: { 'cache-control': 'public, max-age=31536000, immutable' },
		});
		ctx.waitUntil(caches.default.put(request, response.clone()));
		return response;
	},
};
