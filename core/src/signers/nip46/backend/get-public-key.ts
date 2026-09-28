import type { IEventHandlingStrategy, NDKNip46Backend } from "./index.js";

export default class GetPublicKeyHandlingStrategy implements IEventHandlingStrategy {
    async handle(
        backend: NDKNip46Backend,
        _id: string,
        _remotePubkey: string,
        _params: string[],
    ): Promise<string | undefined> {
        if ((backend as any).sessionBinding !== undefined || typeof (backend as any).resolveSession === "function") {
            return (backend as any).sessionBinding?.identityPubkey ?? undefined;
        }
        return backend.localUser?.pubkey;
    }
}
