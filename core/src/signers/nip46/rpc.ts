import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { EventEmitter } from "tseep";
import type { NostrEvent } from "../../events";
import { NDKEvent } from "../../events";
import { NDKKind } from "../../events/kinds";
import type { NDK } from "../../ndk";
import { NDKRelayAuthPolicies } from "../../relay/auth-policies";
import { NDKPool } from "../../relay/pool";
import { NDKRelaySet } from "../../relay/sets";
import { type NDKFilter, type NDKSubscription, NDKSubscriptionCacheUsage } from "../../subscription";
import type { NDKSigner } from "..";

export interface NDKRpcRequest {
    id: string;
    pubkey: string;
    method: string;
    params: string[];
    event: NDKEvent;
}

export interface NDKRpcResponse {
    id: string;
    result: string;
    error?: string;
    event: NDKEvent;
}

export class NDKNostrRpc extends EventEmitter {
    private ndk: NDK;
    private signer: NDKSigner;
    private relaySet: NDKRelaySet | undefined;
    private debug: debug.Debugger;
    public encryptionType: "nip04" | "nip44" = "nip44";
    private pool: NDKPool | undefined;

    public constructor(ndk: NDK, signer: NDKSigner, debug: debug.Debugger, relayUrls?: string[]) {
        super();
        this.ndk = ndk;
        this.signer = signer;

        // if we have relays, we create a separate pool for it
        if (relayUrls) {
            this.pool = new NDKPool(relayUrls, ndk, {
                debug: debug.extend("rpc-pool"),
                name: "Nostr RPC",
            });

            this.relaySet = new NDKRelaySet(new Set(), ndk, this.pool);
            for (const url of relayUrls) {
                const relay = this.pool.getRelay(url, false, false);
                relay.authPolicy = NDKRelayAuthPolicies.signIn({ ndk, signer, debug });
                this.relaySet.addRelay(relay);
                relay.connect();
            }
        }

        this.debug = debug.extend("rpc");
    }

    /**
     * Update relay set.
     * @param relayUrls
     */
    public updateRelays(relayUrls: string[]): void {
        if (!this.pool) {
            this.pool = new NDKPool(relayUrls, this.ndk, {
                debug: this.debug.extend("rpc-pool"),
                name: "Nostr RPC",
            });
        }
        this.relaySet = new NDKRelaySet(new Set(), this.ndk, this.pool);
        for (const url of relayUrls) {
            const relay = this.pool.getRelay(url, false, false);
            if (relay) {
                relay.authPolicy = NDKRelayAuthPolicies.signIn({
                    ndk: this.ndk,
                    signer: this.signer,
                    debug: this.debug,
                });
                this.relaySet.addRelay(relay);
                relay.connect();
            }
        }
    }

    /**
     * Subscribe to a filter. This function will resolve once the subscription is ready.
     */
    public subscribe(filter: NDKFilter): Promise<NDKSubscription> {
        return new Promise((resolve) => {
            const sub = this.ndk.subscribe(filter, {
                closeOnEose: false,
                groupable: false,
                cacheUsage: NDKSubscriptionCacheUsage.ONLY_RELAY,
                pool: this.pool,
                relaySet: this.relaySet,
                onEvent: async (event: NDKEvent) => {
                    try {
                        const parsedEvent = await this.parseEvent(event);
                        if ((parsedEvent as NDKRpcRequest).method) {
                            this.emit("request", parsedEvent);
                        } else {
                            this.emit(`response-${parsedEvent.id}`, parsedEvent);
                            this.emit("response", parsedEvent);
                        }
                    } catch (e) {
                        this.debug("error parsing event", e, event.rawEvent());
                    }
                },
                onEose: () => {
                    this.debug("eosed");
                    resolve(sub);
                },
            });
        });
    }

    public async parseEvent(event: NDKEvent): Promise<NDKRpcRequest | NDKRpcResponse> {
        // support both nip04 and nip44 encryption
        if (this.encryptionType === "nip44" && event.content.includes("?iv=")) {
            this.encryptionType = "nip04";
        } else if (this.encryptionType === "nip04" && !event.content.includes("?iv=")) {
            this.encryptionType = "nip44";
        }

        let remotePubkeyHex = (event as any).uid ?? event.pubkey;
        if (event.key && event.key.includes(":")) {
            try {
                remotePubkeyHex = bytesToHex(base64.decode(event.key.split(":")[1]));
            } catch {
                // fallback
            }
        }

        const remoteUser = this.ndk.getUser({ pubkey: remotePubkeyHex });
        remoteUser.ndk = this.ndk;
        let decryptedContent: string;

        try {
            decryptedContent = await this.signer.decrypt(remoteUser, event.content, this.encryptionType);
        } catch (_e) {
            try {
                const otherEncryptionType = this.encryptionType === "nip04" ? "nip44" : "nip04";
                decryptedContent = await this.signer.decrypt(remoteUser, event.content, otherEncryptionType);
                this.encryptionType = otherEncryptionType;
            } catch {
                throw new Error("Failed to decrypt NIP-46 payload");
            }
        }

        const parsedContent = JSON.parse(decryptedContent);
        const { id, method, params, result, error } = parsedContent;

        if (method) {
            return { id, pubkey: remotePubkeyHex, method, params, event };
        }
        return { id, result, error, event };
    }

    public async sendResponse(
        id: string,
        remotePubkey: string,
        result: string,
        kind = NDKKind.NostrConnect,
        error?: string,
        extraTags?: string[][],
    ): Promise<void> {
        const res = { id, result } as NDKRpcResponse;
        if (error) {
            res.error = error;
        }

        const localUser = await this.signer.user();
        const remoteUser = this.ndk.getUser({ pubkey: remotePubkey });
        const remoteUid = /^[a-f0-9]{64}$/i.test(remotePubkey) ? bytesToHex(sha256(hexToBytes(remotePubkey))) : remotePubkey;
        const tags: string[][] = [
            ["p", remotePubkey],
            ["policy", "allow", "user", remotePubkey],
        ];
        if (remoteUid !== remotePubkey) {
            tags.push(["p", remoteUid]);
            tags.push(["policy", "allow", "user", remoteUid]);
        }
        if (extraTags) {
            tags.push(...extraTags);
        }
        const event = new NDKEvent(this.ndk, {
            kind,
            content: JSON.stringify(res),
            tags,
        } as NostrEvent);
        const localKeyBytes = hexToBytes(localUser.pubkey);
        event.uid = bytesToHex(sha256(localKeyBytes));
        event.key = `secp256k1-schnorr:${base64.encode(localKeyBytes)}`;

        event.content = await this.signer.encrypt(remoteUser, event.content, this.encryptionType);
        await event.sign(this.signer);
        await event.publish(this.relaySet);
    }

    /**
     * Sends a request.
     * @param remotePubkey
     * @param method
     * @param params
     * @param kind
     * @param id
     */
    public async sendRequest(
        remotePubkey: string,
        method: string,
        params: string[] = [],
        kind = 24133,
        cb?: (res: NDKRpcResponse) => void,
    ): Promise<NDKRpcResponse> {
        const id = Math.random().toString(36).substring(7);
        const localUser = await this.signer.user();
        const remoteUser = this.ndk.getUser({ pubkey: remotePubkey });
        const remoteUid = /^[a-f0-9]{64}$/i.test(remotePubkey) ? bytesToHex(sha256(hexToBytes(remotePubkey))) : remotePubkey;
        const request = { id, method, params };
        const promise = new Promise<NDKRpcResponse>((resolve, reject) => {
            const responseHandler = (response: NDKRpcResponse) => {
                if (response.result === "auth_url") {
                    this.once(`response-${id}`, responseHandler);
                    this.emit("authUrl", response.error);
                } else {
                    if (cb) {
                        cb(response);
                    }
                    if (response.error) {
                        reject(new Error(response.error));
                    } else {
                        resolve(response);
                    }
                }
            };

            this.once(`response-${id}`, responseHandler);
        });

        const reqTags: string[][] = [
            ["p", remotePubkey],
            ["policy", "allow", "user", remotePubkey],
        ];
        if (remoteUid !== remotePubkey) {
            reqTags.push(["p", remoteUid]);
            reqTags.push(["policy", "allow", "user", remoteUid]);
        }

        const event = new NDKEvent(this.ndk, {
            kind,
            content: JSON.stringify(request),
            tags: reqTags,
        } as NostrEvent);
        const localKeyBytes = hexToBytes(localUser.pubkey);
        event.uid = bytesToHex(sha256(localKeyBytes));
        event.key = `secp256k1-schnorr:${base64.encode(localKeyBytes)}`;

        event.content = await this.signer.encrypt(remoteUser, event.content, this.encryptionType);
        await event.sign(this.signer);
        await event.publish(this.relaySet);

        return promise;
    }
}
