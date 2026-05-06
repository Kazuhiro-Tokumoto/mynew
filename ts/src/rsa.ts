// rsa.ts

declare const Go: any;

interface RsaKeyPair {
  publicKey: string;
  privateKey: string;
}

interface RsaResult {
  result?: string | boolean;
  error?: string;
}

let wasmReady = false;

export async function initWasm(): Promise<void> {
  const go = new Go();
  const result = await WebAssembly.instantiateStreaming(
    fetch("rsa.wasm"),
    go.importObject
  );
  go.run(result.instance);
  wasmReady = true;
}

function ensureReady() {
  if (!wasmReady) throw new Error("Wasm not initialized. Call initWasm() first.");
}

function timed<T>(label: string, fn: () => T): { value: T; ms: number } {
  const start = performance.now();
  const value = fn();
  const ms = performance.now() - start;
  return { value, ms };
}

export function generateKey(bits: number = 2048): { keys: RsaKeyPair; ms: number } {
  ensureReady();
  const { value, ms } = timed("generateKey", () =>
    (window as any).rsaGenerateKey(bits) as RsaKeyPair & { error?: string }
  );
  if (value.error) throw new Error(value.error);
  return { keys: { publicKey: value.publicKey, privateKey: value.privateKey }, ms };
}

export function encrypt(publicKeyPEM: string, message: string): { ciphertext: string; ms: number } {
  ensureReady();
  const { value, ms } = timed("encrypt", () =>
    (window as any).rsaEncrypt(publicKeyPEM, message) as RsaResult
  );
  if (value.error) throw new Error(value.error);
  return { ciphertext: value.result as string, ms };
}

export function decrypt(privateKeyPEM: string, ciphertext: string): { plaintext: string; ms: number } {
  ensureReady();
  const { value, ms } = timed("decrypt", () =>
    (window as any).rsaDecrypt(privateKeyPEM, ciphertext) as RsaResult
  );
  if (value.error) throw new Error(value.error);
  return { plaintext: value.result as string, ms };
}

export function sign(privateKeyPEM: string, message: string): { signature: string; ms: number } {
  ensureReady();
  const { value, ms } = timed("sign", () =>
    (window as any).rsaSign(privateKeyPEM, message) as RsaResult
  );
  if (value.error) throw new Error(value.error);
  return { signature: value.result as string, ms };
}

export function verify(publicKeyPEM: string, message: string, signature: string): { valid: boolean; ms: number } {
  ensureReady();
  const { value, ms } = timed("verify", () =>
    (window as any).rsaVerify(publicKeyPEM, message, signature) as RsaResult
  );
  if (value.error && value.result !== false) throw new Error(value.error);
  return { valid: value.result as boolean, ms };
}