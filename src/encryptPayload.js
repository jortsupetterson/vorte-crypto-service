export async function handleEncryptionCall(data){
const uuid = crypto.randomUUID();
const iv   = crypto.getRandomValues(new Uint8Array(12));
const salt = crypto.getRandomValues(new Uint8Array(16));

const aesKey = await deriveAesKey(masterKey, salt);

const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, data);

const blob = [
  btoa(String.fromCharCode(...iv)),
  btoa(String.fromCharCode(...ct))
].join(':');

ctx.waitUntil( 
    env.MY_SALT_KV.put(
  `${new Date().toISOString().slice(0,10)}:${uuid}`, 
  btoa(String.fromCharCode(...salt))
)
)

return {
    saltKey:
    cipherText: blob
}
}
const cookie = `${new Date().toISOString().slice(0,10)}:${uuid}:${blob}; Secure; HttpOnly; Path=/;`;
