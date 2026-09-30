import { bytesToHex } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import type { NostrEvent } from "../../events/index.js";
import type { NDK } from "../../ndk/index.js";
import type { NDKEncryptionScheme } from "../../types.js";
import { NDKUser } from "../../user/index.js";
import type { NDKSigner } from "../index.js";
import { NDKMlDsaSigner } from "../ml-dsa/index.js";
import { registerSigner } from "../registry.js";
import {
    kemDecrypt,
    kemEncrypt,
    kemKeygen,
    kemPublicKeyFromSecret,
    parseRawBytes,
    KEM_SECRET_KEY_BYTES,
} from "../kem/index.js";

export interface NDKTransportCredentialOptions {
    kem?: Uint8Array | string;
}

/**
 * A composite credential holding an ML-DSA signing half and an ML-KEM-768 encryption half.
 * Classical ECDH is permanently disposed.
 *
 * Enforces role separation:
 * - sign() uses ML-DSA exclusively.
 * - kemDecaps() uses ML-KEM exclusively.
 * - Classical encrypt/decrypt throw.
 */
export class NDKTransportCredential implements NDKSigner {
    private _signingSigner: NDKMlDsaSigner;
    private _kemSecretKey?: Uint8Array;
    private _kemPublicKey?: Uint8Array;

    public constructor(
        signingKeyOrSigner: Uint8Array | string | NDKMlDsaSigner,
        optionsOrKem?: Uint8Array | string | NDKTransportCredentialOptions | null,
        kemKeyOrNdk?: Uint8Array | string | NDK,
        ndk?: NDK
    ) {
        if (signingKeyOrSigner instanceof NDKMlDsaSigner || typeof (signingKeyOrSigner as any)?.sign === "function") {
            this._signingSigner = signingKeyOrSigner as NDKMlDsaSigner;
        } else {
            this._signingSigner = new NDKMlDsaSigner(signingKeyOrSigner, ndk);
        }

        let kemArg: Uint8Array | string | undefined;

        if (
            optionsOrKem &&
            typeof optionsOrKem === "object" &&
            !(optionsOrKem instanceof Uint8Array) &&
            typeof (optionsOrKem as any).sign !== "function"
        ) {
            kemArg = (optionsOrKem as NDKTransportCredentialOptions).kem;
        } else if (typeof optionsOrKem === "string" || optionsOrKem instanceof Uint8Array) {
            kemArg = optionsOrKem;
        }

        if (!kemArg && (typeof kemKeyOrNdk === "string" || kemKeyOrNdk instanceof Uint8Array)) {
            kemArg = kemKeyOrNdk;
        }

        if (kemArg) {
            this._kemSecretKey = parseRawBytes(kemArg);
            if (this._kemSecretKey.length !== KEM_SECRET_KEY_BYTES) {
                throw new Error(
                    `invalid: ML-KEM-768 secret key must be exactly ${KEM_SECRET_KEY_BYTES} bytes (received ${this._kemSecretKey.length})`
                );
            }
            this._kemPublicKey = kemPublicKeyFromSecret(this._kemSecretKey);
        }
    }

    public static generate(): NDKTransportCredential {
        const signingSigner = NDKMlDsaSigner.generate();
        const kemKey = kemKeygen();
        return new NDKTransportCredential(signingSigner, { kem: kemKey.secretKey });
    }

    get signingSigner(): NDKMlDsaSigner {
        return this._signingSigner;
    }

    get kemPublicKey(): string | undefined {
        return this._kemPublicKey ? bytesToHex(this._kemPublicKey) : undefined;
    }

    get kemPublicKeyBase64(): string | undefined {
        return this._kemPublicKey ? base64.encode(this._kemPublicKey) : undefined;
    }

    get rawKemSecretKey(): Uint8Array | undefined {
        return this._kemSecretKey;
    }

    get rawKemPublicKey(): Uint8Array | undefined {
        return this._kemPublicKey;
    }

    get pubkey(): string {
        return this._signingSigner.pubkey;
    }

    get userSync(): NDKUser {
        return this._signingSigner.userSync;
    }

    public async blockUntilReady(): Promise<NDKUser> {
        return this._signingSigner.blockUntilReady();
    }

    public async user(): Promise<NDKUser> {
        return this._signingSigner.user();
    }

    public async sign(event: NostrEvent): Promise<string> {
        return this._signingSigner.sign(event);
    }

    public kemDecaps(payload: string): string {
        if (!this._kemSecretKey) {
            throw new Error("No KEM secret key configured on transport credential");
        }
        return kemDecrypt(this._kemSecretKey, payload);
    }

    public kemEncaps(recipientKemKey: string | Uint8Array, plaintext: string | Uint8Array): string {
        return kemEncrypt(recipientKemKey, plaintext);
    }

    public async encryptionEnabled(scheme?: NDKEncryptionScheme): Promise<NDKEncryptionScheme[]> {
        if (scheme === "kem" || !scheme) {
            return this._kemSecretKey ? ["kem"] : [];
        }
        return [];
    }

    public async encrypt(recipient: NDKUser, value: string, scheme?: NDKEncryptionScheme): Promise<string> {
        if (scheme === "kem") {
            throw new Error("Local KEM encryption should be performed via kemEncaps() or EDM kemEncrypt()");
        }
        throw new Error("Classical encryption not supported on transport credential (disposed)");
    }

    public async decrypt(sender: NDKUser, value: string, scheme?: NDKEncryptionScheme): Promise<string> {
        if (scheme === "kem") {
            return this.kemDecaps(value);
        }
        throw new Error("Classical decryption not supported on transport credential (disposed)");
    }

    public toPayload(): string {
        const payload = {
            type: "transport-credential",
            payload: JSON.stringify({
                signingPayload: this._signingSigner.toPayload(),
                kemSecretKey: this._kemSecretKey ? bytesToHex(this._kemSecretKey) : undefined,
            }),
        };
        return JSON.stringify(payload);
    }

    public static async fromPayload(payloadString: string, ndk?: NDK): Promise<NDKTransportCredential> {
        const payload = JSON.parse(payloadString);

        if (payload.type !== "transport-credential") {
            throw new Error(`Invalid payload type: expected 'transport-credential', got ${payload.type}`);
        }

        if (!payload.payload || typeof payload.payload !== "string") {
            throw new Error("Invalid payload content for transport-credential signer");
        }

        const inner = JSON.parse(payload.payload);
        const signingSigner = await NDKMlDsaSigner.fromPayload(inner.signingPayload, ndk);

        return new NDKTransportCredential(signingSigner, { kem: inner.kemSecretKey }, ndk);
    }
}

registerSigner("transport-credential", NDKTransportCredential);
