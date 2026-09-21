import type { IEventHandlingStrategy, NDKNip46Backend } from "./index.js";

export default class KemDecryptHandlingStrategy implements IEventHandlingStrategy {
    async handle(
        backend: NDKNip46Backend,
        id: string,
        remotePubkey: string,
        params: string[],
    ): Promise<string | undefined> {
        if (!params || params.length !== 1 || typeof params[0] !== "string" || !params[0]) {
            throw new Error("Invalid parameters: kem_decrypt requires exactly [value]");
        }

        const [payload] = params;
        const decryptedPayload = await decrypt(backend, id, remotePubkey, payload);

        return decryptedPayload;
    }
}

async function decrypt(
    backend: NDKNip46Backend,
    id: string,
    remotePubkey: string,
    payload: string,
) {
    if (
        !(await backend.pubkeyAllowed({
            id,
            pubkey: remotePubkey,
            method: "kem_decrypt",
            params: payload,
        }))
    ) {
        backend.debug(`kem_decrypt request from ${remotePubkey} rejected`);
        return undefined;
    }

    if (typeof (backend.signer as any)?.kemDecrypt === "function") {
        return await (backend.signer as any).kemDecrypt(payload);
    }

    try {
        return await backend.signer.decrypt(undefined as any, payload, "kem");
    } catch (e: any) {
        throw new Error(`KEM decryption is not supported by the configured backend signer: ${e?.message ?? e}`);
    }
}
