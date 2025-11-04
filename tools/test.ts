/**
 * Test suite for the multikey/multibase conversions.
 *
 * Licensed by under the W3C Software and Document License, https://www.w3.org/Consortium/Legal/copyright-software.
 * Copyright ©2025 World Wide Web Consortium. https://www.w3.org/copyright/software-license-2023/
 *
 * @module
 */

import {
    type JWKKeyPair,
    type Multikey,
    type Multibase,
    cryptoToMultikey,
    multikeyToCrypto,
    JWKToMultikey,
    multikeyToJWK,
} from "../index.ts";

// deno-lint-ignore no-explicit-any
export function str(inp: any): void {
    console.log(JSON.stringify(inp, null, 4));
}

class AssertionError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "AssertionError";
    }
}

/**
 * No need for a complex assertion function, just use a simple one.
 */
function assert(condition: boolean, message: string): void {
    if (!condition) {
        throw new AssertionError(message);
    }
}

/**
 * Export a Crypto key pair into a JWK key pair.
 *
 * @param newPair
 */
async function toJWK(newPair: CryptoKeyPair): Promise<JWKKeyPair> {
    const publicKey: JsonWebKey = await crypto.subtle.exportKey("jwk", newPair.publicKey);
    const privateKey: JsonWebKey = await crypto.subtle.exportKey("jwk", newPair.privateKey);
    return { publicKey: publicKey, privateKey: privateKey };
}

/**
 * Compare two JWK public keys, by simply comparing their `x` and, if applicable `y` values.
 * This is _not_ a generic comparison function, only for EDDSA and ECDSA keys, and only for this
 * testing module.
 *
 * @param label - "EDDSA", "ECDSA P-256", or "ECDSA P-384"
 * @param key1
 * @param key2
 */
function compareJWKs(label: string, key1: JsonWebKey, key2: JsonWebKey): boolean {
    if (label === "EDCSA") {
        return key1.x === key2.x;
    } else {
        return key1.x === key2.x && key1.y === key2.y;
    }
}

/**
 * Compare two JWK pairs: compare their public keys and, if applicable, their secret keys. For the latter, the `d` values
 * are also compared (used by both ECDSA and EDDSA).
 *
 * @param label - "EDDSA", "ECDSA P-256", or "ECDSA P-384"
 * @param pair1
 * @param pair2
 */
function compareJWKPairs(label: string, pair1: JWKKeyPair, pair2: JWKKeyPair): boolean {
    const public_equal: boolean = compareJWKs(label,  pair1.publicKey, pair2.publicKey);
    if (pair1.privateKey) {
        if (pair2.privateKey) {
            const private_equal: boolean =
                compareJWKs(label, pair1.privateKey, pair2.privateKey) &&
                pair1.privateKey.d === pair2.privateKey.d;
            return public_equal && private_equal;
        } else {
            // both must have the private key!
            return false;
        }
    } else {
        return public_equal
    }
}

/************************************************************
 Roundtrip with single crypto public key
 *************************************************************/

/**
 * Convert a single crypto key to multibase, then convert it back; see if the two crypto keys are identical.
 * This comparison is made by exporting both keys into JWK and compare those.
 *
 * @param label -"EDDSA", "ECDSA P-256", or "ECDSA P-384"
 * @param key
 */
async function singleCrypto(label: string, key: CryptoKey): Promise<boolean> {
    const mk:    Multibase = await cryptoToMultikey(key);
    const newCr: CryptoKey = await multikeyToCrypto(mk);

    // For debugging, both keys are converted into JWK
    const key_jwk = await crypto.subtle.exportKey("jwk", key);
    const gen_jwk = await crypto.subtle.exportKey("jwk", newCr);

    return compareJWKs(label,  key_jwk, gen_jwk)
}

Deno.test("1.1 EDDSA crypto public key -> MK -> Crypto", async (): Promise<void> => {
    const eddsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await singleCrypto("EDDSA", eddsaPair.publicKey);
    assert(compare, "Roundtrip single Crypto public key does not work with EDDSA");
});

Deno.test("1.2 EDDSA crypto public key -> MK -> Crypto", async (): Promise<void> => {
    const ecdsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await singleCrypto("ECDSA P-256", ecdsaPair.publicKey);
    assert(compare, "Roundtrip single Crypto public key does not work with ECDSA P-256");
});

Deno.test("1.3 EDDSA crypto public key -> MK -> Crypto", async (): Promise<void> => {
    const ecdsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await singleCrypto("ECDSA P-384", ecdsaPair.publicKey);
    assert(compare, "Roundtrip single Crypto public key does not work with ECDSA P-384");
});

/****************************************************************
 Roundtrip with full Crypto pairs (i.e., public and secret keys)
 ****************************************************************/
/**
 * Convert a crypto private/public key pair to multikey, then convert them back; see if the two crypto key pairs are identical.
 * This comparison is made by exporting both keys into JWK pairs and compare those.
 *
 * @param label -"EDDSA", "ECDSA P-256", or "ECDSA P-384"
 * @param pair
 */
async function onePairCrypto(label: string, pair: CryptoKeyPair): Promise<boolean> {
    const mk: Multikey = await cryptoToMultikey(pair);
    const newPair: CryptoKeyPair = await multikeyToCrypto(mk);

    // For debugging, both keypairs are converted into JWK
    const keyPair = await toJWK(pair);
    const mkPair  = await toJWK(newPair);
    return compareJWKPairs(label,  keyPair, mkPair);
}

Deno.test("2.1 EDDSA crypto keypair -> MK -> Crypto", async (): Promise<void> => {
    const eddsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await onePairCrypto("EDDSA", eddsaPair);
    assert(compare, "Roundtrip full Crypto does not work with EDDSA");
});

Deno.test("2.2 ECDSA P-256 crypto keypair -> MK -> Crypto", async (): Promise<void> => {
    const ecdsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await onePairCrypto("ECDSA P-256", ecdsaPair);
    assert(compare, "Roundtrip full Crypto does not work with ECDSA P-256");
});

Deno.test("2.3 ECDSA P-384 crypto keypair -> MK -> Crypto", async (): Promise<void> => {
    const ecdsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await onePairCrypto("ECDSA P-384", ecdsaPair);
    assert(compare, "Roundtrip full Crypto does not work with ECDSA P-384");
});

/************************************************************
 Roundtrip with single JWK public key
 *************************************************************/

/**
 * Convert a single crypto key to a Json Web Key, convert this to
 * multibase, then convert it back into JWK; see if the two JWK keys are identical.
 *
 * @param label -"EDDSA", "ECDSA P-256", or "ECDSA P-384"
 * @param key
 */
async function singleJWK(label: string, key: CryptoKey): Promise<boolean> {
    const key_jwk: JsonWebKey = await crypto.subtle.exportKey("jwk", key);
    const mk: Multibase       = JWKToMultikey(key_jwk);
    const gen_jwk: JsonWebKey = multikeyToJWK(mk);

    return compareJWKs(label,  key_jwk, gen_jwk)
}

Deno.test("3.1 EDDSA crypto public key -> JWK -> MB -> JWK", async (): Promise<void> => {
    const eddsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await singleJWK("EDDSA",  eddsaPair.publicKey);
    assert(compare, "Roundtrip single JWK public key does not work with EDDSA");
});

Deno.test("3.2 ECDSA P-256 crypto public key -> JWK -> MB -> JWK", async (): Promise<void> => {
    const ecdsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await singleJWK("ECDSA P-256",  ecdsaPair.publicKey);
    assert(compare, "Roundtrip single JWK public key does not work with ECDSA P-256");
});

Deno.test("3.3 ECDSA P-384 crypto public key -> JWK -> MB -> JWK", async (): Promise<void> => {
    const ecdsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await singleJWK("ECDSA P-384",  ecdsaPair.publicKey);
    assert(compare, "Roundtrip single JWK public key does not work with ECDSA P-384");
});

/************************************************************
 Roundtrip with full JWK pairs (i.e., public and secret keys)
 ************************************************************/

/**
 * Convert a crypto private/public key pair to a pair of JWK keys, convert this pair to
 * multikey, then convert it back into JWK; see if the two JWK key pairs are identical.
 *
 * @param label -"EDDSA", "ECDSA P-256", or "ECDSA P-384"
 * @param pair
 */
async function onePairJWK(label: string, pair: CryptoKeyPair): Promise<boolean> {
    const keyPair: JWKKeyPair = await toJWK(pair);
    const mk: Multikey        = JWKToMultikey(keyPair);
    const mkPair: JWKKeyPair  = multikeyToJWK(mk);

    return compareJWKPairs(label, keyPair, mkPair);
}

Deno.test("4.1 EDDSA crypto keypair -> JWK -> MK -> JWK", async (): Promise<void> => {
    const eddsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await onePairJWK("EDDSA", eddsaPair);
    assert(compare, "Roundtrip JWK pair does not work with EDDSA");
});

Deno.test("4.2 ECDSA P-256 crypto keypair -> JWK -> MK -> JWK", async (): Promise<void> => {
    const ecdsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await onePairJWK("ECDSA P-256", ecdsaPair);
    assert(compare, "Roundtrip JWK pair does not work with ECDSA P-256");
});

Deno.test("4.3 ECDSA P-384 crypto keypair -> JWK -> MK -> JWK", async (): Promise<void> => {
    const ecdsaPair: CryptoKeyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const compare = await onePairJWK("ECDSA P-384", ecdsaPair);
    assert(compare, "Roundtrip JWK pair does not work with ECDSA P-384");
});
