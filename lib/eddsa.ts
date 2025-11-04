/**
 * Base conversion functions for EDDSA. The functions are straightforward, but the interfaces are made so that
 * they coincide with the companion functions in ECDSA.
 *
 * Licensed by under the W3C Software and Document License, https://www.w3.org/Consortium/Legal/copyright-software.
 * Copyright ©2025 World Wide Web Consortium. https://www.w3.org/copyright/software-license-2023/
 *
 * @module
 */
import type { JWKKeyPair, MultikeyBinary, CryptoCurves } from "./common.ts";
import { base64urlnopad as base64 }                      from "npm:@scure/base@2.0.0";

/**
 * Convert the Crypto values from JWK to the equivalent Multikey Pairs' binary data.
 * The final encoding, with preambles, are done in the general level.
 *
 * For EDDSA, this is essentially, an empty function, which simply returns the `x` and `d` values. The
 * interface is there to be reused by the ECDSA equivalent, which must do some extra processing.
 *
 * @param _curve - unused in this function, just a placeholder
 * @param x - x value for the elliptical curve, as extracted from JWK
 * @param d - d (private) value for the elliptical curve, as extracted from JWK
 * @param _y - unused in this function, just a placeholder
 * @returns
 */
export function JWKToMultikeyBinary(_curve: CryptoCurves, x: Uint8Array, d: Uint8Array | undefined, _y?: Uint8Array): MultikeyBinary {
    return {
        public: x,
        secret: d,
    }
}

/**
 * Convert the multikey values to their JWK equivalents. The final `x` and `d` values are encoded
 * in base64 and then the relevant JWK structure are created
 *
 * For EDDSA, this is a very straightforward operation by just encoding the values and plugging them into a
 * constant JWK structure. The interface is there to be reused by the ECDSA equivalent, which must
 * do some extra processing.
 *
 * @param _curve - unused in this function, just a placeholder
 * @param xb - binary version of the x value for the elliptical curve
 * @param db - binary version of the d value for the elliptical curve
 * @returns
 */
export function multikeyBinaryToJWK(_curve: CryptoCurves, xb: Uint8Array, db?: Uint8Array): JWKKeyPair {
    const x = base64.encode(xb);
    const output: JWKKeyPair = {
        publicKey: {
            kty: "OKP",
            crv: "Ed25519",
            x,
            key_ops: [
                "verify"
            ],
            ext: true
        }
    };

    if (db !== undefined) {
        output.privateKey = {
            kty: "OKP",
            crv: "Ed25519",
            x,
            d : base64.encode(db),
            key_ops: [
                "sign"
            ],
            ext: true
        };
    }
    return output;
}
