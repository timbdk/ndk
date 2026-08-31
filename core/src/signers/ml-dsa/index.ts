import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import type { NostrEvent } from "../../events/index.js";
import { serializeEvent } from "../../events/serializer.js";
import type { NDK } from "../../ndk/index.js";
import type { NDKEncryptionScheme } from "../../types.js";
import { NDKUser } from "../../user";
import type { NDKSigner } from "../index.js";
import { registerSigner } from "../registry.js";

/**
 * A signer that uses an in-memory ML-DSA-44 private key.
 * Signs event IDs with ML-DSA-44. Encryption methods throw because ML-DSA cannot encrypt.
 */
export class NDKMlDsaSigner implements NDKSigner {
    private _user: NDKUser;
    private _privateKey: Uint8Array;
    private _publicKey: Uint8Array;
    private _pubkey: string;

    public constructor(privateKey: Uint8Array | string, ndk?: NDK) {
        if (typeof privateKey === "string") {
            if (privateKey.includes(":")) {
                const b64 = privateKey.substring(privateKey.indexOf(":") + 1);
                this._privateKey = base64.decode(b64);
            } else if (/^[a-f0-9]+$/i.test(privateKey) && privateKey.length % 2 === 0) {
                this._privateKey = hexToBytes(privateKey);
            } else {
                this._privateKey = base64.decode(privateKey);
            }
        } else {
            this._privateKey = privateKey;
        }

        if (this._privateKey.length !== ml_dsa44.lengths.secretKey) {
            throw new Error(`invalid: ML-DSA-44 secret key must be exactly ${ml_dsa44.lengths.secretKey} bytes (received ${this._privateKey.length})`);
        }
        this._publicKey = ml_dsa44.getPublicKey(this._privateKey);
        this._pubkey = bytesToHex(this._publicKey);

        if (ndk) this._user = ndk.getUser({ pubkey: this._pubkey });
        this._user ??= new NDKUser({ pubkey: this._pubkey });
    }

    public static generate(): NDKMlDsaSigner {
        const keys = ml_dsa44.keygen();
        return new NDKMlDsaSigner(keys.secretKey);
    }

    public static fromSeed(seed: Uint8Array): NDKMlDsaSigner {
        const expectedSeedLen = ml_dsa44.lengths.seed ?? 32;
        if (seed.length !== expectedSeedLen) {
            throw new Error(`invalid: seed must be exactly ${expectedSeedLen} bytes`);
        }
        const keys = ml_dsa44.keygen(seed);
        return new NDKMlDsaSigner(keys.secretKey);
    }

    get privateKey(): string {
        if (!this._privateKey) throw new Error("Not ready");
        return bytesToHex(this._privateKey);
    }

    get rawPrivateKey(): Uint8Array {
        return this._privateKey;
    }

    get publicKey(): string {
        return this._pubkey;
    }

    get rawPublicKey(): Uint8Array {
        return this._publicKey;
    }

    get pubkey(): string {
        if (!this._pubkey) throw new Error("Not ready");
        return this._pubkey;
    }

    get userSync(): NDKUser {
        return this._user;
    }

    public async blockUntilReady(): Promise<NDKUser> {
        return this._user;
    }

    public async user(): Promise<NDKUser> {
        return this._user;
    }

    public async sign(event: NostrEvent): Promise<string> {
        if (!this._privateKey) {
            throw new Error("Attempted to sign without a private key");
        }

        let messageBytes: Uint8Array;
        if (event.id) {
            messageBytes = hexToBytes(event.id);
        } else {
            const serialized = serializeEvent(event);
            const hash = sha256(new TextEncoder().encode(serialized));
            event.id = bytesToHex(hash);
            messageBytes = hash;
        }

        const signature = ml_dsa44.sign(messageBytes, this._privateKey);
        return bytesToHex(signature);
    }

    public async encryptionEnabled(_scheme?: NDKEncryptionScheme): Promise<NDKEncryptionScheme[]> {
        throw new Error("ML-DSA signer does not support encryption");
    }

    public async encrypt(_recipient: NDKUser, _value: string, _scheme?: NDKEncryptionScheme): Promise<string> {
        throw new Error("ML-DSA signer does not support encryption");
    }

    public async decrypt(_sender: NDKUser, _value: string, _scheme?: NDKEncryptionScheme): Promise<string> {
        throw new Error("ML-DSA signer does not support decryption");
    }

    public toPayload(): string {
        if (!this._privateKey) throw new Error("Private key not available");
        const payload = {
            type: "ml-dsa",
            payload: this.privateKey,
        };
        return JSON.stringify(payload);
    }

    public static async fromPayload(payloadString: string, ndk?: NDK): Promise<NDKMlDsaSigner> {
        const payload = JSON.parse(payloadString);

        if (payload.type !== "ml-dsa") {
            throw new Error(`Invalid payload type: expected 'ml-dsa', got ${payload.type}`);
        }

        if (!payload.payload || typeof payload.payload !== "string") {
            throw new Error("Invalid payload content for ml-dsa signer");
        }

        return new NDKMlDsaSigner(payload.payload, ndk);
    }
}

registerSigner("ml-dsa", NDKMlDsaSigner);
