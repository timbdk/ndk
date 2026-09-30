import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { EventEmitter } from "tseep";
import type { NostrEvent } from "../../events";
import { NDKEvent } from "../../events";
import type { NDK } from "../../ndk";
import { NDKRelayAuthPolicies } from "../../relay/auth-policies";
import { NDKPool } from "../../relay/pool";
import { NDKRelaySet } from "../../relay/sets";
import { type NDKFilter, type NDKSubscription, NDKSubscriptionCacheUsage } from "../../subscription";
import type { NDKSigner } from "..";
import { kemEncrypt } from "../kem/index.js";

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

export interface NDKNostrRpcOptions {
    envelopeMode?: "kem";
    requestPeerKemKey?: string;
    resolvePeerKemKey?: (recipientUid: string) => Promise<string | undefined> | string | undefined;
    responseCapable?: boolean;
}

export class NDKNostrRpc extends EventEmitter {
    private ndk: NDK;
    private signer: NDKSigner;
    private relaySet: NDKRelaySet | undefined;
    private debug: debug.Debugger;
    public envelopeMode: "kem";
    public requestPeerKemKey?: string;
    public resolvePeerKemKey?: (recipientUid: string) => Promise<string | undefined> | string | undefined;
    public bunkerPubkey?: string;
    private pool: NDKPool | undefined;

    public constructor(
        ndk: NDK,
        signer: NDKSigner,
        debug: debug.Debugger,
        relayUrls?: string[],
        options?: NDKNostrRpcOptions,
    ) {
        super();
        this.ndk = ndk;
        this.signer = signer;
        this.envelopeMode = "kem";
        this.requestPeerKemKey = options?.requestPeerKemKey;
        this.resolvePeerKemKey = options?.resolvePeerKemKey;

        const isResponseCapable = options?.responseCapable === true;
        if (isResponseCapable && !this.resolvePeerKemKey) {
            throw new Error("Response-capable KEM RPC instance requires resolvePeerKemKey");
        }

        // if we have relays, we create a separate pool for it
        if (relayUrls?.length) {
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

        this.debug = debug?.extend ? debug.extend("rpc") : ndk.debug.extend("rpc");
    }

    /**
     * Update relay set.
     * @param relayUrls
     */
    public updateRelays(relayUrls: string[]): void {
        if (!relayUrls.length) {
            this.debug("updateRelays called with empty relay list, ignoring");
            return;
        }
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
                        if (!parsedEvent) {
                            return;
                        }
                        if ("method" in parsedEvent) {
                            this.emit("request", parsedEvent);
                        } else {
                            const response = parsedEvent as NDKRpcResponse;
                            if (response.error?.includes("KEM_STALE_KEY")) {
                                this.emit("kem_stale_key", response);
                                const listeners = (this as any).eventNames?.() || [];
                                for (const name of listeners) {
                                    if (typeof name === "string" && name.startsWith("response-")) {
                                        this.emit(name, response);
                                    }
                                }
                            }
                            this.emit(`response-${response.id}`, response);
                            this.emit("response", response);
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

    public async parseEvent(event: NDKEvent): Promise<NDKRpcRequest | NDKRpcResponse | null> {
        const authorUid = (event as any).uid ?? event.pubkey;
        let decryptedContent: string;

        if (!event.content || !event.content.startsWith("kem1:")) {
            this.debug("rejecting non-kem1 event in kem envelopeMode", event.rawEvent());
            return null;
        }
        try {
            if (typeof (this.signer as any)?.kemDecaps === "function") {
                decryptedContent = (this.signer as any).kemDecaps(event.content);
            } else if (typeof (this.signer as any)?.kemDecrypt === "function") {
                decryptedContent = await (this.signer as any).kemDecrypt(event.content);
            } else {
                decryptedContent = await this.signer.decrypt(undefined as any, event.content, "kem");
            }
        } catch (e) {
            this.debug("error decapsulating KEM event", e, event.rawEvent());
            this.emit("decapsulation:failed", { event, error: e });
            return null;
        }

        let parsedContent: any;
        try {
            parsedContent = JSON.parse(decryptedContent);
        } catch (e) {
            this.debug("error parsing decrypted content as JSON", e, event.rawEvent());
            return null;
        }
        const { id, method, params, result, error } = parsedContent;

        if (method) {
            return { id, pubkey: authorUid, method, params, event };
        }
        return { id, result, error, event };
    }

    /**
     * Sends a response to a request.
     * @param id
     * @param remotePubkey
     * @param result
     * @param kind
     * @param error
     * @param extraTags
     */
    public async sendResponse(
        id: string,
        remotePubkey: string,
        result: string,
        kind = 24133,
        error?: string,
        extraTags?: string[][],
    ): Promise<void> {
        const res = { id, result } as NDKRpcResponse;
        if (error) {
            res.error = error;
        }

        const localUser = await this.signer.user();
        const remoteKeyBytes = hexToBytes(remotePubkey);
        const remoteUid = remoteKeyBytes.length === 32 ? remotePubkey : bytesToHex(sha256(remoteKeyBytes));
        const targetP = remotePubkey.length === 2624 ? remoteUid : remotePubkey;

        const tags: string[][] = [
            ["p", targetP],
            ["policy", "allow", "user", targetP],
        ];
        if (remoteUid !== targetP) {
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
        if (localKeyBytes.length !== 1312) {
            throw new Error(`NDKNostrRpc requires an ML-DSA-44 signer, got key length ${localKeyBytes.length}`);
        }
        event.key = `ml-dsa-44:${base64.encode(localKeyBytes)}`;

        if (!this.resolvePeerKemKey) {
            throw new Error(
                `No recipient KEM public key available for response to ${remotePubkey}: resolvePeerKemKey is not configured`
            );
        }
        let recipientKemKey = await this.resolvePeerKemKey(remotePubkey);
        if (!recipientKemKey && remoteUid !== remotePubkey) {
            recipientKemKey = await this.resolvePeerKemKey(remoteUid);
        }
        if (!recipientKemKey) {
            this.debug?.(
                `No recipient KEM public key available for response to ${remotePubkey}: resolvePeerKemKey returned no key, skipping send`
            );
            return;
        }
        event.content = kemEncrypt(recipientKemKey, event.content);

        await event.sign(this.signer);
        await event.publish(this.relaySet);
    }

    /**
     * Sends a request.
     * @param remotePubkey
     * @param method
     * @param params
     * @param kind
     * @param cb
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
        const remoteKeyBytes = hexToBytes(remotePubkey);
        const remoteUid = remoteKeyBytes.length === 32 ? remotePubkey : bytesToHex(sha256(remoteKeyBytes));
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

        const targetP = remotePubkey.length === 2624 ? remoteUid : remotePubkey;
        const reqTags: string[][] = [
            ["p", targetP],
            ["policy", "allow", "user", targetP],
        ];
        if (remoteUid !== targetP) {
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
        if (localKeyBytes.length !== 1312) {
            throw new Error(`NDKNostrRpc requires an ML-DSA-44 signer, got key length ${localKeyBytes.length}`);
        }
        event.key = `ml-dsa-44:${base64.encode(localKeyBytes)}`;

        if (!this.requestPeerKemKey) {
            throw new Error("Cannot send KEM RPC request: requestPeerKemKey is not configured");
        }
        event.content = kemEncrypt(this.requestPeerKemKey, event.content);

        await event.sign(this.signer);
        await event.publish(this.relaySet);

        return promise;
    }
}
