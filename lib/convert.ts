/**
 * The real work for the whole library are done in the main functions in this module.
 *
 * Licensed by under the W3C Software and Document License, https://www.w3.org/Consortium/Legal/copyright-software.
 * Copyright ©2025 World Wide Web Consortium. https://www.w3.org/copyright/software-license-2023/
 *
 * @module
 */

import {
    type JWKKeyPair, type Multikey, type Multibase, type Preamble,
    CryptoCurves, CryptoKeyTypes, type CryptoKeyData,
    ECDSACurves,
    type MultikeyBinary,
    classToPreamble, classToDecoder, classToEncoder,
    preambleToCryptoData
} from "./common.ts";

// deno-lint-ignore no-import-prefix
import { base64urlnopad as base64, base58 } from "npm:@scure/base@2.0.0";

/****************************************************************************************/
/* The real converter functions                                                         */
/****************************************************************************************/
/**
 * Generic function to convert a multikey pair to JWK. This function decodes the multikey data
 * into a binary buffer, checks the preambles and invokes the crypto curve specific converter functions
 * (depending on the preamble values) that do the final conversion from the binary data to JWK.
 *
 * Works for ecdsa (both P-384 and P-256), and eddsa.
 *
 * @param keys
 * @returns
 * @throws - exceptions if something is incorrect in the incoming data
 */
export function multikeyToJWK(keys: Multikey): JWKKeyPair {
    // Separate the preamble from the real binary key value.
    interface MultikeyData {
        preamble:  Preamble<number>,
        keyBinary: Uint8Array;
    }
    // Separate the preamble of a multikey from the key value. By doing so,
    // the initial 'z' value is also removed.
    const convertBinary = (key: Multibase): MultikeyData => {
        // Check whether the first character is a 'z' before removing it
        if (key[0] === 'z') {
            const unencoded_key: Uint8Array = base58.decode(key.slice(1));
            return {
                preamble  : [unencoded_key[0], unencoded_key[1]],
                keyBinary : unencoded_key.slice(2),
            };
        } else {
            throw new Error(`"${key}" is not encoded as required (first character should be a 'z')`);
        }
    };

    // Get the the public values values...
    const publicBinary = convertBinary(keys.publicKeyMultibase);
    // ... and find out, based on the preamble, which curve is used and whether it is indeed public
    const publicData: CryptoKeyData = preambleToCryptoData(publicBinary.preamble);
    if (publicData.crType !== CryptoKeyTypes.PUBLIC) {
        throw new Error(`"${keys.publicKeyMultibase}" has the wrong preamble (should refer to a public key).`);
    }

    // Get hold of the curve specific converter function that will do the real work on the binary
    // data
    const converter = classToDecoder[publicData.crCurve];

    // We have to repeat the previous steps for a secret key, if applicable, before converting the result into a JWK pair,
    // A check is made on the fly to see that the keys are compatible in terms of crypto methods
    if (keys.secretKeyMultibase) {
        const secretBinary = convertBinary(keys.secretKeyMultibase);
        const secretData: CryptoKeyData = preambleToCryptoData(secretBinary.preamble);

        if (secretData.crCurve !== publicData.crCurve) {
            throw new Error(`Private and secret keys have different crypto methods`);
        } else if (secretData.crType !== CryptoKeyTypes.SECRET) {
            throw new Error(`"${keys.secretKeyMultibase}" has the wrong preamble (should refer to a secret key).`);
        }

        // Everything seems to be fine
        return converter(publicData.crCurve, publicBinary.keyBinary, secretBinary.keyBinary);
    } else {
        return converter(publicData.crCurve, publicBinary.keyBinary);
    }
}


/**
 * Convert JWK Key pair to Multikeys. This function decodes the JWK keys, finds out which binary key it encodes
 * and converts the key to the multikey versions depending on the exact curve.
 *
 * Note that the code does not check (yet?) all combination of the JWK pairs where they would be erroneous, only
 * those that would lead to error in this cose. E.g., it does not check whether the x (and possibly y) values
 * are identical in the secret and private JWK keys.
 *
 * Works for ecdsa (both P-384 and P-256), and eddsa.

 * @param keys
 */
export function JWKToMultikey(keys: JWKKeyPair): Multikey {
    // Internal function for the common last step of encoding a multikey
    const encodeMultikey = (val: Uint8Array, preamble: Preamble<number>): string => {
        const val_mk = new Uint8Array([...preamble, ...val]);
        return 'z' + base58.encode(val_mk);
    }

    const decodeJWKField = (val: string | undefined): Uint8Array | undefined => {
        if (val === undefined) {
            return undefined
        } else {
            return base64.decode(val);
        }
    }

    // Find out the key curve, will be used for branching later: is it ECDSA or EDDSA and, if the former,
    // which one?
    const keyCurve = (key: JsonWebKey): CryptoCurves => {
        if (key.kty) {
            if (key.kty === "EC") {
                switch (key.crv) {
                    case "P-256": return CryptoCurves.ECDSA_256;
                    case "P-384": return CryptoCurves.ECDSA_384;
                    default: throw new Error(`Unknown crv value for an ecdsa key (${key.crv})`);
                }
            } else if (key.kty === "OKP") {
                if (key.crv === "Ed25519") {
                    return CryptoCurves.EDDSA
                } else {
                    throw new Error(`Unknown crv value for an OKP key (${key.crv})`)
                }
            } else {
                throw new Error(`Unknown kty value for a key (${key.kty})`)
            }
        } else {
            throw new Error(`No kty value for the key (${JSON.stringify(key)})`)
        }
    };

    const publicKeyCurve = keyCurve(keys.publicKey);

    // The secret key class is calculated, but this is just for checking; the two must be identical...
    if (keys.privateKey !== undefined) {
        const secretKeyCurve = keyCurve(keys.privateKey);
        if (publicKeyCurve !== secretKeyCurve) {
            throw new Error(`Public and private keys refer to different EC curves (${JSON.stringify(keys)})`);
        }
    }

    // The cryptokey values are x, y (for ecdsa), and d (for the secret key).
    // Each of these are base 64 encoded strings; what we need is the
    // binary versions thereof.
    const x: Uint8Array | undefined = decodeJWKField(keys.publicKey.x);
    if (x === undefined) {
        throw new Error(`x value is missing from public key (${JSON.stringify(keys.publicKey)})`);
    }

    const y: Uint8Array | undefined = decodeJWKField(keys.publicKey.y);
    if (ECDSACurves.includes(publicKeyCurve) && y === undefined) {
        throw new Error(`y value is missing from the ECDSA public key (${JSON.stringify(keys.publicKey)})`);
    }

    const d: Uint8Array | undefined = (keys.privateKey) ? decodeJWKField(keys.privateKey.d) : undefined;
    if (keys.privateKey && d === undefined) {
        throw new Error(`d value is missing from private key  (${JSON.stringify(keys)})`);
    }

    const converter = classToEncoder[publicKeyCurve]
    const finalBinary: MultikeyBinary = converter(publicKeyCurve, x, d, y);

    // We have the binary version of the multikey values, this must be converted into real multikey.
    // This means adding a preamble and convert to base58.
    const preambles = classToPreamble[publicKeyCurve];
    const output: Multikey = {
        publicKeyMultibase : encodeMultikey(finalBinary.public, preambles.public)
    }
    if (finalBinary.secret !== undefined) {
        output.secretKeyMultibase = encodeMultikey(finalBinary.secret, preambles.secret);
    }
    return output;
}




