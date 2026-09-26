/**
 * ML-KEM-768 key encapsulation primitives and kem1: wire format handling for NDK transport envelopes.
 * Note: Must remain strictly wire-format compatible with event-data-module/kem.ts.
 */
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { concatBytes, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

export const KEM_PUBLIC_KEY_BYTES = 1184;
export const KEM_SECRET_KEY_BYTES = 2400;
export const KEM_CIPHERTEXT_BYTES = 1088;
export const KEM_SHARED_SECRET_BYTES = 32;
export const KEM_NONCE_BYTES = 12;
export const KEM_TAG_BYTES = 16;

export function parseRawBytes(input: Uint8Array | string): Uint8Array {
    if (input instanceof Uint8Array) return input;
    if (typeof input === "string") {
        if (input.includes(":")) {
            const b64 = input.substring(input.indexOf(":") + 1);
            return base64.decode(b64);
        }
        if (/^[a-f0-9]+$/i.test(input) && input.length % 2 === 0) {
            return hexToBytes(input);
        }
        return base64.decode(input);
    }
    throw new Error("invalid: key material must be Uint8Array or string");
}

export function kemKeygen(seed?: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array } {
    const kp = ml_kem768.keygen(seed);
    return {
        secretKey: kp.secretKey,
        publicKey: kp.publicKey,
    };
}

export function kemPublicKeyFromSecret(sk: Uint8Array | string): Uint8Array {
    const skBytes = parseRawBytes(sk);
    if (skBytes.length !== KEM_SECRET_KEY_BYTES) {
        throw new Error(`invalid: ML-KEM-768 secret key must be exactly ${KEM_SECRET_KEY_BYTES} bytes (received ${skBytes.length})`);
    }
    return ml_kem768.getPublicKey(skBytes);
}

export function kemEncaps(pk: Uint8Array | string): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
    const pkBytes = parseRawBytes(pk);
    if (pkBytes.length !== KEM_PUBLIC_KEY_BYTES) {
        throw new Error(`invalid: ML-KEM-768 public key must be exactly ${KEM_PUBLIC_KEY_BYTES} bytes (received ${pkBytes.length})`);
    }
    const res = ml_kem768.encapsulate(pkBytes);
    return {
        ciphertext: res.cipherText,
        sharedSecret: res.sharedSecret,
    };
}

export function kemDecaps(sk: Uint8Array | string, ciphertext: Uint8Array | string): Uint8Array {
    const skBytes = parseRawBytes(sk);
    const ctBytes = parseRawBytes(ciphertext);
    if (skBytes.length !== KEM_SECRET_KEY_BYTES) {
        throw new Error(`invalid: ML-KEM-768 secret key must be exactly ${KEM_SECRET_KEY_BYTES} bytes (received ${skBytes.length})`);
    }
    if (ctBytes.length !== KEM_CIPHERTEXT_BYTES) {
        throw new Error(`invalid: ML-KEM-768 ciphertext must be exactly ${KEM_CIPHERTEXT_BYTES} bytes (received ${ctBytes.length})`);
    }
    return ml_kem768.decapsulate(ctBytes, skBytes);
}

export function parseKemPayload(payload: string): { version: "kem1"; ciphertext: Uint8Array; nonce: Uint8Array; payload: Uint8Array } {
    if (typeof payload !== "string") {
        throw new Error("invalid: payload must be a string");
    }
    const parts = payload.split(":");
    if (parts.length !== 3) {
        throw new Error(`invalid: malformed KEM payload format, expected 3 segments (got ${parts.length})`);
    }
    const [version, ctB64, payloadB64] = parts;
    if (version !== "kem1") {
        throw new Error(`invalid: unsupported KEM payload version '${version}'`);
    }
    let ctBytes: Uint8Array;
    try {
        ctBytes = base64.decode(ctB64);
    } catch {
        throw new Error("invalid: malformed base64 in KEM ciphertext segment");
    }
    if (ctBytes.length !== KEM_CIPHERTEXT_BYTES) {
        throw new Error(`invalid: KEM ciphertext segment must be exactly ${KEM_CIPHERTEXT_BYTES} bytes (received ${ctBytes.length})`);
    }
    let combinedPayload: Uint8Array;
    try {
        combinedPayload = base64.decode(payloadB64);
    } catch {
        throw new Error("invalid: malformed base64 in KEM symmetric payload segment");
    }
    const minPayloadBytes = KEM_NONCE_BYTES + KEM_TAG_BYTES;
    if (combinedPayload.length < minPayloadBytes) {
        throw new Error(`invalid: KEM symmetric payload too short (minimum ${minPayloadBytes} bytes for nonce and tag, received ${combinedPayload.length})`);
    }
    const nonce = combinedPayload.subarray(0, KEM_NONCE_BYTES);
    const symmetricPayload = combinedPayload.subarray(KEM_NONCE_BYTES);
    return {
        version: "kem1",
        ciphertext: ctBytes,
        nonce,
        payload: symmetricPayload,
    };
}

export function kemEncrypt(recipientKemPublicKey: Uint8Array | string, plaintext: string | Uint8Array): string {
    const { ciphertext, sharedSecret } = kemEncaps(recipientKemPublicKey);
    const nonce = randomBytes(KEM_NONCE_BYTES);
    const plaintextBytes = typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
    const cipher = chacha20poly1305(sharedSecret, nonce);
    const encrypted = cipher.encrypt(plaintextBytes);
    const combinedPayload = concatBytes(nonce, encrypted);
    return `kem1:${base64.encode(ciphertext)}:${base64.encode(combinedPayload)}`;
}

export function kemDecrypt(recipientKemSecretKey: Uint8Array | string, payload: string): string {
    const parsed = parseKemPayload(payload);
    const sharedSecret = kemDecaps(recipientKemSecretKey, parsed.ciphertext);
    const cipher = chacha20poly1305(sharedSecret, parsed.nonce);
    try {
        const decryptedBytes = cipher.decrypt(parsed.payload);
        return new TextDecoder().decode(decryptedBytes);
    } catch (err: any) {
        throw new Error(`invalid: AEAD decryption failed (${err?.message || "tag mismatch"})`);
    }
}
