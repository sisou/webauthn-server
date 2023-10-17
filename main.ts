import { z } from "https://deno.land/x/zod/mod.ts";

import { createChallenge, deleteChallenge, getChallenge } from "./stores/challenge.ts";
import { getPublicKeyData, setPublicKeyData } from "./stores/publicKey.ts";

function cors(request: Request) {
    return {
        headers: {
            "Access-Control-Allow-Origin": request.headers.get("origin") || "*",
        },
    };
}

const handler = (request: Request): Response | Promise<Response> => {
    if (request.method === "OPTIONS") {
        return new Response(null, {
            headers: {
                ...cors(request).headers,
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type",
            },
        });
    }

    const url = new URL(request.url);

    switch (url.pathname) {
        case "/": {
            return new Response("Hello world!", { status: 200, ...cors(request) });
        }
        case "/register": {
            switch (request.method) {
                case "POST": {
                    return registrationHandler(request);
                }
                default: {
                    return new Response("Method not allowed", { status: 405, ...cors(request) });
                }
            }
        }
        case "/challenge": {
            switch (request.method) {
                case "GET": {
                    return createLoginChallenge(request);
                }
                case "POST": {
                    return verifyLoginChallenge(request);
                }
                default: {
                    return new Response("Method not allowed", { status: 405, ...cors(request) });
                }
            }
        }
        default: {
            return new Response("Not found", { status: 404, ...cors(request) });
        }
    }
};

async function registrationHandler(request: Request): Promise<Response> {
    const schema = z.object({
        credentialId: z.string(), // TODO: Verify base64 format
        algorithm: z.number(), // COSEAlgorithmIdentifier
        spkiPublicKey: z.string(), // TODO: Verify hex format
        multisigPubKey: z.string(), // TODO: Verify hex format
    });

    const { credentialId, spkiPublicKey, algorithm, multisigPubKey } = schema.parse(await request.json());

    try {
        await setPublicKeyData(credentialId, {
            version: 3,
            spkiPublicKey,
            algorithm,
            createdAt: Math.floor(Date.now() / 1000),
            multisigPubKey,
        });
        return new Response("OK", { status: 200, ...cors(request) });
    } catch (error) {
        return new Response(error.message, { status: 500, ...cors(request) });
    }
}

async function createLoginChallenge(request: Request): Promise<Response> {
    return new Response(await createChallenge(), { status: 200, ...cors(request) });
}

async function verifyLoginChallenge(request: Request): Promise<Response> {
    const schema = z.object({
        credentialId: z.string(), // TODO: Verify base64 format
        authenticatorData: z.string(), // TODO: Verify hex format
        clientDataJSON: z.string(), // TODO: Verify hex format
        asn1Signature: z.string(), // TODO: Verify hex format
    });

    const {
        credentialId,
        authenticatorData: authenticatorDataHex,
        clientDataJSON: clientDataJSONHex,
        asn1Signature: asn1SignatureHex,
    } = schema.parse(await request.json());

    const authenticatorData = fromHex(authenticatorDataHex);
    const clientDataJSON = fromHex(clientDataJSONHex);
    const asn1Signature = fromHex(asn1SignatureHex);

    const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON)) as {
        type: string;
        challenge: string;
        origin: string;
        crossOrigin?: boolean; // Android Chrome does not include this field
    };

    if (clientData.type !== "webauthn.get") {
        return new Response("Invalid type", { status: 400, ...cors(request) });
    }

    // Verify the request comes from the origin included in the clientData
    if (clientData.origin !== request.headers.get("origin")) {
        return new Response("Origin mismatch", { status: 400, ...cors(request) });
    }

    const hostname = new URL(clientData.origin).hostname;

    // Calculate the RP ID hash and compare it with the authenticatorData
    const rpIdHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(hostname)));
    if (
        !rpIdHash.every((byte, index) => {
            return byte === authenticatorData[index];
        })
    ) {
        return new Response("RP ID hash mismatch", { status: 400, ...cors(request) });
    }

    // Fetch the challenge from the database
    const challenge = await getChallenge(clientData.challenge);
    if (!challenge) {
        return new Response("Challenge not found", { status: 404, ...cors(request) });
    }
    if (challenge !== clientData.challenge) {
        return new Response("Challenge mismatch", { status: 400, ...cors(request) });
    }

    // Fetch the public key from the database
    const pubkeyData = await getPublicKeyData(credentialId);
    if (!pubkeyData) {
        return new Response("Key ID not found", { status: 404, ...cors(request) });
    }

    let verified = false;

    if (!pubkeyData.algorithm || pubkeyData.algorithm !== -7) {
        // Import public key
        const importedPublicKey = await crypto.subtle.importKey(
            "spki",
            fromHex(pubkeyData.spkiPublicKey),
            {
                name: "ECDSA",
                namedCurve: "P-256",
                hash: { name: "SHA-256" },
            },
            false,
            ["verify"],
        );

        // Verify the signature
        const signatureBase = new Uint8Array([
            ...authenticatorData,
            ...new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON)),
        ]);

        // Convert signature from ASN.1 sequence to "raw" format
        const rStart = asn1Signature[4] === 0 ? 5 : 4;
        const rEnd = rStart + 32;
        const sStart = asn1Signature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
        const r = asn1Signature.slice(rStart, rEnd);
        const s = asn1Signature.slice(sStart);
        const rawSignature = new Uint8Array([...r, ...s]);

        verified = await crypto.subtle.verify(
            {
                name: "ECDSA",
                // namedCurve: "P-256",
                hash: { name: "SHA-256" },
            },
            importedPublicKey,
            rawSignature,
            signatureBase,
        );
    }

    if (pubkeyData.algorithm !== -8) {
        // Import public key
        const importedPublicKey = await crypto.subtle.importKey(
            "spki",
            fromHex(pubkeyData.spkiPublicKey),
            {
                name: "Ed25519",
            },
            false,
            ["verify"],
        );

        // Verify the signature
        const signatureBase = new Uint8Array([
            ...authenticatorData,
            ...new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON)),
        ]);

        // Convert signature from ASN.1 sequence to "raw" format
        const rStart = asn1Signature[4] === 0 ? 5 : 4;
        const rEnd = rStart + 32;
        const sStart = asn1Signature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
        const r = asn1Signature.slice(rStart, rEnd);
        const s = asn1Signature.slice(sStart);
        const rawSignature = new Uint8Array([...r, ...s]);

        verified = await crypto.subtle.verify(
            {
                name: "Ed25519",
            },
            importedPublicKey,
            rawSignature,
            signatureBase,
        );
    }

    if (!verified) {
        return new Response("Signature verification failed", { status: 400, ...cors(request) });
    }

    // Delete the challenge
    await deleteChallenge(challenge);

    return new Response(JSON.stringify(pubkeyData), { status: 200, ...cors(request) });
}

function fromHex(hex: string): Uint8Array {
    return new Uint8Array(hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));
}

const port = parseInt(Deno.env.get("PORT") || "8080");
Deno.serve({ port }, handler);
