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

/**
 * A composite credential holding an ML-DSA signing half and a classical ECDH encryption half.
 * Signs events via ML-DSA and encrypts/decrypts payloads via NIP-44 with the ECDH key.
 */
export class NDKTransportCredential implements NDKSigner {
    private _signingSigner: NDKMlDsaSigner;
    private _ecdhSigner: NDKPrivateKeySigner;

    public constructor(
        signingKeyOrSigner: Uint8Array | string | NDKMlDsaSigner,
        ecdhKeyOrSigner: Uint8Array | string | NDKPrivateKeySigner,
        ndk?: NDK
    ) {
        if (signingKeyOrSigner instanceof NDKMlDsaSigner) {
            this._signingSigner = signingKeyOrSigner;
        } else {
            this._signingSigner = new NDKMlDsaSigner(signingKeyOrSigner, ndk);
        }

        if (ecdhKeyOrSigner instanceof NDKPrivateKeySigner) {
            this._ecdhSigner = ecdhKeyOrSigner;
        } else {
            this._ecdhSigner = new NDKPrivateKeySigner(ecdhKeyOrSigner, ndk);
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

    get ecdhSigner(): NDKPrivateKeySigner {
        return this._ecdhSigner;
    }

    get encPublicKey(): string {
        return this._ecdhSigner.pubkey;
    }

    get encPublicKeyBase64(): string {
        return base64.encode(hexToBytes(this._ecdhSigner.pubkey));
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

    public async encryptionEnabled(scheme?: NDKEncryptionScheme): Promise<NDKEncryptionScheme[]> {
        return this._ecdhSigner.encryptionEnabled(scheme);
    }

    public async encrypt(recipient: NDKUser, value: string, scheme?: NDKEncryptionScheme): Promise<string> {
        return this._ecdhSigner.encrypt(recipient, value, scheme);
    }

    public async decrypt(sender: NDKUser, value: string, scheme?: NDKEncryptionScheme): Promise<string> {
        return this._ecdhSigner.decrypt(sender, value, scheme);
    }

    public toPayload(): string {
        const payload = {
            type: "transport-credential",
            payload: JSON.stringify({
                signingPayload: this._signingSigner.toPayload(),
                ecdhPayload: this._ecdhSigner.toPayload(),
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
        const ecdhSigner = await NDKPrivateKeySigner.fromPayload(inner.ecdhPayload, ndk);

        return new NDKTransportCredential(signingSigner, ecdhSigner, ndk);
    }
}

registerSigner("transport-credential", NDKTransportCredential);
