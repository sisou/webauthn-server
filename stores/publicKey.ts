const KEY = "public key";

export async function setSpkiPublicKey(credentialId: string, spkiPublicKey: string): Promise<void> {
    const kv = await Deno.openKv();
    const res = await kv.set([KEY, credentialId], spkiPublicKey);
    if (!res.ok) {
        throw new Error("Failed to set public key");
    }
}

export async function getSpkiPublicKey(credentialId: string): Promise<string | null> {
    const kv = await Deno.openKv();
    return (await kv.get<string>([KEY, credentialId])).value;
}
