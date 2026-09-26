import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import type { NostrEvent } from "../../events/index.js";
import type { NDK } from "../../ndk/index.js";
import type { NDKEncryptionScheme } from "../../types.js";
import { NDKUser } from "../../user";
import type { NDKSigner } from "../index.js";
import { NDKMlDsaSigner } from "../ml-dsa/index.js";
import { NDKPrivateKeySigner } from "../private-key/index.js";
import { registerSigner } from "../registry.js";
import {
    kemDecrypt,
    kemEncrypt,
    kemPublicKeyFromSecret,
    parseRawBytes,
    KEM_SECRET_KEY_BYTES,
} from "../kem/index.js";

export interface NDKTransportCredentialOptions {
    ecdh?: Uint8Array | string | NDKPrivateKeySigner;
    kem?: Uint8Array | string;
}

/**
 * A composite credential holding an ML-DSA signing half, an optional ML-KEM-768 half,
 * and an optional classical ECDH encryption half (during the dual-window transition).
 *
 * Enforces role separation:
 * - sign() uses ML-DSA exclusively.
 * - kemDecaps() uses ML-KEM exclusively.
 * - Calling classical encrypt/decrypt throws when ECDH half is absent (e.g. on client).
 */
export class NDKTransportCredential implements NDKSigner {
    private _signingSigner: NDKMlDsaSigner;
    private _ecdhSigner?: NDKPrivateKeySigner;
    private _kemSecretKey?: Uint8Array;
    private _kemPublicKey?: Uint8Array;

    public constructor(
        signingKeyOrSigner: Uint8Array | string | NDKMlDsaSigner,
        ecdhOrOptions?: Uint8Array | string | NDKPrivateKeySigner | NDKTransportCredentialOptions | null,
        kemKeyOrNdk?: Uint8Array | string | NDK,
        ndk?: NDK
    ) {
        if (signingKeyOrSigner instanceof NDKMlDsaSigner || typeof (signingKeyOrSigner as any)?.sign === "function") {
            this._signingSigner = signingKeyOrSigner as NDKMlDsaSigner;
        } else {
            this._signingSigner = new NDKMlDsaSigner(signingKeyOrSigner, ndk);
        }

        let effectiveNdk = ndk;
        let ecdhArg: Uint8Array | string | NDKPrivateKeySigner | undefined;
        let kemArg: Uint8Array | string | undefined;

        if (
            ecdhOrOptions &&
            typeof ecdhOrOptions === "object" &&
            !(ecdhOrOptions instanceof NDKPrivateKeySigner) &&
            !(ecdhOrOptions instanceof Uint8Array) &&
            typeof (ecdhOrOptions as any).sign !== "function"
        ) {
            ecdhArg = (ecdhOrOptions as NDKTransportCredentialOptions).ecdh;
            kemArg = (ecdhOrOptions as NDKTransportCredentialOptions).kem;
            if (kemKeyOrNdk && typeof (kemKeyOrNdk as any)?.pool !== "undefined") {
                effectiveNdk = kemKeyOrNdk as NDK;
            }
        } else {
            ecdhArg = (ecdhOrOptions as Uint8Array | string | NDKPrivateKeySigner) ?? undefined;
            if (kemKeyOrNdk && typeof (kemKeyOrNdk as any)?.pool !== "undefined") {
                effectiveNdk = kemKeyOrNdk as NDK;
            } else if (kemKeyOrNdk) {
                kemArg = kemKeyOrNdk as Uint8Array | string;
            }
        }

        if (ecdhArg) {
            if (ecdhArg instanceof NDKPrivateKeySigner || typeof (ecdhArg as any)?.sign === "function") {
                this._ecdhSigner = ecdhArg as NDKPrivateKeySigner;
            } else {
                this._ecdhSigner = new NDKPrivateKeySigner(ecdhArg, effectiveNdk);
            }
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
        const ecdhSigner = NDKPrivateKeySigner.generate();
        return new NDKTransportCredential(signingSigner, ecdhSigner);
    }

    get signingSigner(): NDKMlDsaSigner {
        return this._signingSigner;
    }

    get ecdhSigner(): NDKPrivateKeySigner | undefined {
        return this._ecdhSigner;
    }

    get encPublicKey(): string | undefined {
        return this._ecdhSigner?.pubkey;
    }

    get encPublicKeyBase64(): string | undefined {
        return this._ecdhSigner ? base64.encode(hexToBytes(this._ecdhSigner.pubkey)) : undefined;
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
        if (scheme === "kem") {
            return this._kemSecretKey ? ["kem"] : [];
        }
        if (this._ecdhSigner) {
            return this._ecdhSigner.encryptionEnabled(scheme);
        }
        return [];
    }

    public async encrypt(recipient: NDKUser, value: string, scheme?: NDKEncryptionScheme): Promise<string> {
        if (scheme === "kem") {
            throw new Error("Local KEM encryption should be performed via kemEncaps() or EDM kemEncrypt()");
        }
        if (!this._ecdhSigner) {
            throw new Error("Classical encryption not supported on this credential (ECDH half absent)");
        }
        return this._ecdhSigner.encrypt(recipient, value, scheme);
    }

    public async decrypt(sender: NDKUser, value: string, scheme?: NDKEncryptionScheme): Promise<string> {
        if (scheme === "kem") {
            return this.kemDecaps(value);
        }
        if (!this._ecdhSigner) {
            throw new Error("Classical decryption not supported on this credential (ECDH half absent)");
        }
        return this._ecdhSigner.decrypt(sender, value, scheme);
    }

    public toPayload(): string {
        const payload = {
            type: "transport-credential",
            payload: JSON.stringify({
                signingPayload: this._signingSigner.toPayload(),
                ecdhPayload: this._ecdhSigner?.toPayload(),
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
        const ecdhSigner = inner.ecdhPayload ? await NDKPrivateKeySigner.fromPayload(inner.ecdhPayload, ndk) : undefined;

        return new NDKTransportCredential(signingSigner, { ecdh: ecdhSigner, kem: inner.kemSecretKey }, ndk);
    }
}

registerSigner("transport-credential", NDKTransportCredential);
