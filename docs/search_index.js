(function () {
  window.DENO_DOC_SEARCH_INDEX = {"nodes":[{"kind":["interface"],"name":"JWKKeyPair","file":".","doc":"","location":{"filename":"","line":5,"col":0,"byteIndex":76},"url":"././~/JWKKeyPair.html","category":"","declarationKind":"export","deprecated":false},{"kind":["function","function","function"],"name":"JWKToMultikey","file":".","doc":"Convert JWK Key pair to Multikeys. This function decodes the JWK keys, finds out which binary key it encodes\nand converts the key to the multikey versions depending on the exact curve.\n\nNote that the code does not check (yet?) all combination of the JWK pairs and fields for possible errors, only\nthose that would lead to error in this package. E.g., it does not check whether the x (and possibly y) values\nare identical in the secret and private JWK keys.\n\nWorks for ecdsa (both P-384 and P-256), and eddsa.\n","location":{"filename":"default","line":41,"col":0,"byteIndex":1863},"url":"././~/JWKToMultikey.html","category":"","declarationKind":"export","deprecated":false},{"kind":["typeAlias"],"name":"Multikey","file":".","doc":"Type for a Multikey\n\nOne day this could become a string with a fixed regexp...","location":{"filename":"","line":27,"col":0,"byteIndex":601},"url":"././~/Multikey.html","category":"","declarationKind":"export","deprecated":false},{"kind":["interface"],"name":"MultikeyPair","file":".","doc":"The specification is a bit fuzzy and talks about Multikey for a pair, and for individual constituents.\nWe need to differentiate those two...","location":{"filename":"","line":33,"col":0,"byteIndex":788},"url":"././~/MultikeyPair.html","category":"","declarationKind":"export","deprecated":false},{"kind":["function","function","function"],"name":"MultikeyToJWK","file":".","doc":"Generic function to convert a multikey pair to JWK. This function decodes the multikey data\ninto a binary buffer, checks the preambles and invokes the crypto specific converter functions \n(depending on the preamble values) that do the final\nconversion from the binary data to JWK.\n\nWorks for ecdsa (both P-384 and P-256), and eddsa.\n","location":{"filename":"default","line":16,"col":0,"byteIndex":752},"url":"././~/MultikeyToJWK.html","category":"","declarationKind":"export","deprecated":false}]};
})()