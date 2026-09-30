import type { NDKSigner } from "../signers";
/**
 * Encryption and gift-wrapping of events
 * Implements Nip04, Nip44, Nip59
 */
import type { NDKEncryptionScheme } from "../types";
import type { NDKUser } from "../user";
import type { NDKEvent } from "./index.js";

export type EncryptionMethod = "encrypt" | "decrypt";

export async function encrypt(
    this: NDKEvent,
    recipient?: NDKUser,
    signer?: NDKSigner,
    scheme: NDKEncryptionScheme = "kem",
): Promise<void> {
    if (scheme !== "kem") {
        throw new Error(`Unsupported encryption scheme '${scheme}': only 'kem' is supported`);
    }
    throw new Error("KEM encryption is browser-local; no NDKEvent.encrypt exists");
}

export async function decrypt(
    this: NDKEvent,
    sender?: NDKUser,
    signer?: NDKSigner,
    scheme: NDKEncryptionScheme = "kem",
): Promise<void> {
    if (scheme && scheme !== "kem") {
        throw new Error(`Unsupported encryption scheme '${scheme}': only 'kem' is supported`);
    }

    // Check if we have this decrypted event in cache
    if (this.ndk?.cacheAdapter?.getDecryptedEvent) {
        const cachedEvent = await this.ndk.cacheAdapter.getDecryptedEvent(this.id);

        // If we found a cached decrypted event, use its content
        if (cachedEvent) {
            this.content = cachedEvent.content;
            return;
        }
    }

    let decrypted: string | undefined;
    if (!this.ndk) throw new Error("No NDK instance found!");
    let currentSigner = signer;
    if (!currentSigner) {
        this.ndk.assertSigner();
        currentSigner = this.ndk.signer;
    }
    if (!currentSigner) throw new Error("no NDK signer");

    const currentSender = sender || this.author;
    if (!currentSender) throw new Error("No sender provided and no author available");

    decrypted = (await currentSigner.decrypt(currentSender, this.content, "kem")) as string;
    if (!decrypted) throw new Error("Failed to decrypt event.");

    this.content = decrypted;

    // Cache the decrypted event if we have a cache adapter that supports it
    // For regular encrypted events (not gift-wrapped), the event ID itself is the cache key
    if (this.ndk?.cacheAdapter?.addDecryptedEvent) {
        this.ndk.cacheAdapter.addDecryptedEvent(this.id, this);
    }
}
