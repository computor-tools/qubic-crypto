/**
 * Expects compiled binaries with Emscripten, of XKCP/12 and Microsoft/FourQlib/FourQ_64bit_and_portable.
 * 
 * License
 * 
 * -- For Microsof/FourQlib
 * 
 * MIT License
 * 
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 * 
 * 
 * -- For XKCP/K12 binaries
 * 
 * K12 based on the eXtended Keccak Code Package (XKCP)
 * https://github.com/XKCP/XKCP
 * 
 * KangarooTwelve, designed by Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche, Ronny Van Keer and Benoît Viguier.
 * 
 * Implementation by Gilles Van Assche and Ronny Van Keer, hereby denoted as "the implementer".
 * 
 * For more information, feedback or questions, please refer to the Keccak Team website:
 * https://keccak.team/
 * 
 * To the extent possible under law, the implementer has waived all copyright
 * and related or neighboring rights to the source code in this file.
 * http://creativecommons.org/publicdomain/zero/1.0/
 *
 * 
 * -- For the JavaScript code that follows:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH 
 * THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

'use strict'

import factory from './crypto.cjs';

const PRIVATE_KEY_LENGTH = 32;
const PUBLIC_KEY_LENGTH = 32;
const SIGNATURE_LENGTH = 64;

const methods = factory().then((instance) => ({
    generatePublicKey: (sk, pk) => instance._generatePublicKey(sk.byteOffset, pk.byteOffset),
    sign: (sk, pk, m, msize, s) => instance._sign(sk.byteOffset, pk.byteOffset, m.byteOffset, msize, s.byteOffset),
    verify: (pk, m, msize, s) => instance._verify(pk.byteOffset, m.byteOffset, msize, s.byteOffset),
    generateCompressedPublicKey: (sk, pk) => instance._generateCompressedPublicKey(sk.byteOffset,  pk.byteOffset),
    compressedSecretAgreement: (sk, pk, ssk) => instance._compressedSecretAgreement(sk.byteOffset, pk.byteOffset, ssk.byteOffset),
    K12: (inp, inpsize, out, outsize) => instance._K12(inp.byteOffset, inpsize, out.byteOffset, outsize),
    free: (chunk) => instance._free(chunk.byteOffset),
    allocU8(size, value = new Uint8Array(size).fill(0)) {
        const ptr = instance._malloc(size);
        const chunk = instance.HEAPU8.subarray(ptr, ptr + size);
        chunk.set(value);
        return chunk;
    },
}));

const crypto = {
    PRIVATE_KEY_LENGTH,
    PUBLIC_KEY_LENGTH,
    SIGNATURE_LENGTH,
    DIGEST_LENGTH: 32,
    NONCE_LENGTH: 32,
    async generatePublicKey(secretKey) {
        if (secretKey.byteLength !== PRIVATE_KEY_LENGTH) {
            throw new RangeError('Invalid private key length.');
        }
        const { generatePublicKey, allocU8, free } = await methods;
        const sk = allocU8(PRIVATE_KEY_LENGTH, secretKey);
        const pk = allocU8(PRIVATE_KEY_LENGTH);
        if (generatePublicKey(sk, pk)) {
            const out = pk.slice();
            free(sk);
            free(pk);
            return out;
        } else {
            throw new Error('Public key generation failed!');
        }
    },
    async sign(secretKey, publicKey, message) {
        if (secretKey.byteLength !== PRIVATE_KEY_LENGTH) {
            throw new RangeError('Invalid private key length.');
        }
        if (publicKey.byteLength !== PUBLIC_KEY_LENGTH) {
            throw new RangeError('Invalid public key length.');
        }
        const { sign, allocU8, free } = await methods;
        const sk = allocU8(PRIVATE_KEY_LENGTH, secretKey);
        const pk = allocU8(PRIVATE_KEY_LENGTH, publicKey);
        const m = allocU8(message.byteLength, message);
        const s = allocU8(SIGNATURE_LENGTH);
        if (sign(sk, pk, m, message.byteLength, s)) {
            const out = s.slice();
            free(sk);
            free(pk);
            free(m);
            free(s);
            return out;
        } else {
            throw new Error('Signature generation failed!');
        }
    },

    async verify(publicKey, message, signature) {
        if (publicKey.byteLength !== PUBLIC_KEY_LENGTH) {
            throw new RangeError('Invalid public key length.');
        }
        if (signature.byteLength !== SIGNATURE_LENGTH) {
            throw new RangeError('Invalid signature length.');
        }
        const { verify, allocU8, free } = await methods;
        const pk = allocU8(PRIVATE_KEY_LENGTH, publicKey);
        const m = allocU8(message.byteLength, message);
        const s = allocU8(SIGNATURE_LENGTH, signature);
        const valid = verify(pk, m, message.byteLength, s);
        free(pk);
        free(m);
        free(s);
        return valid;
    },

    async generateCompressedPublicKey(secretKey) {
        if (secretKey.byteLength !== PRIVATE_KEY_LENGTH) {
            throw new RangeError('Invalid private key length.');
        }
        const { generateCompressedPublicKey, allocU8, free } = await methods;
        const sk = allocU8(PRIVATE_KEY_LENGTH, secretKey);
        const pk = allocU8(PRIVATE_KEY_LENGTH);
        if (generateCompressedPublicKey(sk, pk)) {
            const out = pk.slice();
            free(sk);
            free(pk);
            return out;
        } else {
            throw new Error('Compressed public key generation failed!');
        }
    },

    async compressedSecretAgreement(secretKey, publicKey) {
        if (secretKey.byteLength !== PRIVATE_KEY_LENGTH) {
            throw new RangeError('Invalid private key length.');
        }
        if (publicKey.byteLength !== PUBLIC_KEY_LENGTH) {
            throw new RangeError('Invalid public key length.');
        }
        const { compressedSecretAgreement, allocU8, free } = await methods;
        const sk = allocU8(PRIVATE_KEY_LENGTH, secretKey);
        const pk = allocU8(PRIVATE_KEY_LENGTH);
        const ssk = allocU8(SHARED_SECRET_KENTH);
        if (compressedSecretAgreement(sk, pk, ssk)) {
            const out = ssk.slice();
            free(sk);
            free(pk);
            free(ssk);
            return out;
        } else {
            throw new Error('Compressed secret agreement failed!');
        }
    },

    async K12(input, output, outputSize, outputOffset = 0) {
        if (output.byteLength < outputSize) {
            throw new RangeError('Invalid output size.');
        }
        const { K12, allocU8, free } = await methods;
        const inp = allocU8(input.byteLength, input);
        const out = allocU8(outputSize);
        if (K12(inp, input.byteLength, out, outputSize)) {
            output.set(out.slice(), outputOffset);
            free(inp);
            free(out);
        } else {
            throw new Error('K12 failed!');
        }
    },
};

export default crypto;
