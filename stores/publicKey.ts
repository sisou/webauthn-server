const KEY = "public key";

type PublicKeyRecordV1 = string;

type PublicKeyRecordV2 = {
    version: 2,
    spkiPublicKey: string, // hex
    createdAt: number, // unix timestamp (seconds)
    lastAccessedAt?: number, // unix timestamp (seconds)
    multisigPubKey: string, // hex
};

type PublicKeyRecordV3 = Omit<PublicKeyRecordV2, 'version'> & {
    version: 3,
    algorithm: number, // COSEAlgorithmIdentifier
};

type PublicKeyRecord = PublicKeyRecordV1 | PublicKeyRecordV2;

export type PublicKeyData = {
    spkiPublicKey: string, // hex
    algorithm?: number, // COSEAlgorithmIdentifier
    createdAt?: number, // unix timestamp (seconds)
    lastAccessedAt?: number, // unix timestamp (seconds)
    multisigPubKey?: string, // hex
};

export async function setPublicKeyData(credentialId: string, data: PublicKeyRecordV3): Promise<void> {
    const kv = await Deno.openKv();
    const res = await kv.set([KEY, credentialId], data);
    if (!res.ok) {
        throw new Error("Failed to set public key data");
    }
}

export async function getPublicKeyData(credentialId: string): Promise<PublicKeyData | null> {
    const kv = await Deno.openKv();
    const record =(await kv.get<PublicKeyRecord>([KEY, credentialId])).value;
    if (!record) {
        return null;
    }

    if (typeof record === "string") {
        return {
            spkiPublicKey: record,
        };
    }

    // Update lastAccessedAt
    const now = Math.floor(Date.now() / 1000);
    if (!record.lastAccessedAt || record.lastAccessedAt < now) {
        record.lastAccessedAt = now;
        await kv.set([KEY, credentialId], record);
    }

    const { version: _, ...data} = record;

    return data;
}
