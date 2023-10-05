const KEY = "challenge";

function makeChallengeId(challenge: string) {
    return challenge.substring(0, 8);
}

export async function createChallenge(): Promise<string> {
    const kv = await Deno.openKv();

    let challenge: string;
    let res;

    do {
        challenge = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
            .replaceAll("/", "_")
            .replaceAll("+", "-")
            .replaceAll("=", "");
        const id = makeChallengeId(challenge);

        res = await kv.atomic()
            .check({ key: ["challenge", id], versionstamp: null })
            .set(["challenge", id], challenge, { expireIn: 2 * 60e3 })
            .commit(); // Expires after 2 minutes
    } while (!res.ok);

    return challenge;
}

export async function getChallenge(challenge: string): Promise<string | null> {
    const kv = await Deno.openKv();
    return (await kv.get<string>([KEY, makeChallengeId(challenge)])).value;
}

export async function deleteChallenge(challenge: string): Promise<void> {
    const kv = await Deno.openKv();
    await kv.delete([KEY, makeChallengeId(challenge)]);
}
