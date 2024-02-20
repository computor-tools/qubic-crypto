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
 * Permission is hereby granted, perpetual, worldwide, non-exclusive, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
 * to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * 
 * 1. The Software cannot be used in any form or in any substantial portions for development, maintenance and for any other purposes, in the military sphere and in relation to military products, 
 * including, but not limited to:
 * 
 *    a. any kind of armored force vehicles, missile weapons, warships, artillery weapons, air military vehicles (including military aircrafts, combat helicopters, military drones aircrafts), 
 *    air defense systems, rifle armaments, small arms, firearms and side arms, melee weapons, chemical weapons, weapons of mass destruction;
 *
 *    b. any special software for development technical documentation for military purposes;
 *
 *    c. any special equipment for tests of prototypes of any subjects with military purpose of use;
 *
 *    d. any means of protection for conduction of acts of a military nature;
 *
 *    e. any software or hardware for determining strategies, reconnaissance, troop positioning, conducting military actions, conducting special operations;
 *
 *    f. any dual-use products with possibility to use the product in military purposes;
 *
 *    g. any other products, software or services connected to military activities;
 *
 *    h. any auxiliary means related to abovementioned spheres and products.
 *
 *
 * 2. The Software cannot be used as described herein in any connection to the military activities. A person, a company, or any other entity, which wants to use the Software, 
 * shall take all reasonable actions to make sure that the purpose of use of the Software cannot be possibly connected to military purposes.
 *
 *
 * 3. The Software cannot be used by a person, a company, or any other entity, activities of which are connected to military sphere in any means. If a person, a company, or any other entity, 
 * during the period of time for the usage of Software, would engage in activities, connected to military purposes, such person, company, or any other entity shall immediately stop the usage 
 * of Software and any its modifications or alterations.
 *
 *
 * 4. Abovementioned restrictions should apply to all modification, alteration, merge, and to other actions, related to the Software, regardless of how the Software was changed due to the 
 * abovementioned actions.
 *
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions, modifications and alterations of the Software.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH 
 * THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

'use strict'

import factory from './crypto.cjs';

const ALPHABET = 'abcdefghijklmnopqrstuvwxyz';

const SEED_LENGTH = 55;
const PRIVATE_KEY_LENGTH = 32;
const PUBLIC_KEY_LENGTH = 32;
const SIGNATURE_LENGTH = 64;
const SHARED_SECRET_LENGTH = 32;
const DIGEST_LENGTH = 32;
const NONCE_LENGTH = 32;

const methods = factory().then((instance) => ({
    generatePublicKey: (sk, pk) => instance._generatePublicKey(sk.byteOffset, pk.byteOffset),
    sign: (sk, pk, m, msize, s) => instance._sign(sk.byteOffset, pk.byteOffset, m.byteOffset, msize, s.byteOffset),
    verify: (pk, m, msize, s) => instance._verify(pk.byteOffset, m.byteOffset, msize, s.byteOffset),
    generateCompressedPublicKey: (sk, pk) => instance._generateCompressedPublicKey(sk.byteOffset,  pk.byteOffset),
    compressedSecretAgreement: (sk, pk, ssk) => instance._compressedSecretAgreement(sk.byteOffset, pk.byteOffset, ssk.byteOffset),
    K12: (inp, inpsize, out, outsize) => instance._K12(inp.byteOffset, inpsize, out.byteOffset, outsize),
    merkleRoot: (depth, index, data, datalen, siblings, root) => instance._merkleRoot(depth, index, data.byteOffset, datalen, siblings.byteOffset, root.byteOffset),
    verifySolution: (
        dataLength,
        infoLength,
        numberOfInputNeurons,
        numberOfOutputNeurons,
        maxInputDuration,
        maxOutputDuration,
        neuronValueLimit,
        randomSeed,
        solutionThreshold,
        computorPublicKey,
        nonce,
    ) => {
        instance._verifySolution(
            dataLength,
            infoLength,
            numberOfInputNeurons,
            numberOfOutputNeurons,
            maxInputDuration,
            maxOutputDuration,
            neuronValueLimit.byteOffset,
            randomSeed.byteOffset,
            solutionThreshold,
            computorPublicKey.byteOffset,
            nonce.byteOffset,
        );
    },
    free: (chunk) => instance._free(chunk.byteOffset),
    allocU8(size, value = new Uint8Array(size).fill(0)) {
        const ptr = instance._malloc(size);
        const chunk = instance.HEAPU8.subarray(ptr, ptr + size);
        chunk.set(value);
        return chunk;
    },
}));

const crypto = {
    SEED_LENGTH,
    PRIVATE_KEY_LENGTH,
    PUBLIC_KEY_LENGTH,
    SIGNATURE_LENGTH,
    SHARED_SECRET_LENGTH,
    DIGEST_LENGTH,
    NONCE_LENGTH,

    async createPrivateKey(seed, index = 0) {
        if (Object.prototype.toString.call(seed) === '[object Uint8Array]' && seed.length !== SEED_LENGTH) {
            for (let i = 0; i < SEED_LENGTH; i++) {
                if (seed[i] > ALPHABET.indexOf('z')) {
                    throw new TypeError('Invalid seed.');
                }
            }
        } else {
            if (new RegExp(`^[a-z]{${SEED_LENGTH}}$`).test(seed) === false) {
                throw new TypeError('Invalid seed.');
            }

            const bytes = new Uint8Array(SEED_LENGTH);
            for (let i = 0; i < SEED_LENGTH; i++) {
              bytes[i] = ALPHABET.indexOf(seed[i]);
            }
            seed = bytes;
        }
        if (!Number.isInteger(index)) {
            throw new TypeError('Invalid index');
        }
    
        const privateKey = new Uint8Array(PRIVATE_KEY_LENGTH);
        const preimage = seed.slice();
        while (index-- > 0) {
            for (let i = 0; i < preimage.length; i++) {
                if (++preimage[i] > ALPHABET.length) {
                    preimage[i] = 1;
                } else {
                    break;
                }
            }
        }

        const { K12, allocU8, free } = await methods;
        const inp = allocU8(SEED_LENGTH, preimage);
        const out = allocU8(PRIVATE_KEY_LENGTH);
        if (K12(inp, SEED_LENGTH, out, PRIVATE_KEY_LENGTH)) {
            privateKey.set(out.slice());
            free(inp);
            free(out);
        } else {
            free(inp);
            free(out);
            throw new Error('K12 failed!');
        }
    
        return privateKey;
    },

    async generatePublicKey(secretKey) {
        if (secretKey.byteLength !== PRIVATE_KEY_LENGTH) {
            throw new RangeError('Invalid private key length!');
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
            free(sk);
            free(pk);
            throw new Error('Public key generation failed!');
        }
    },

    async sign(secretKey, publicKey, message) {
        if (secretKey.byteLength !== PRIVATE_KEY_LENGTH) {
            throw new RangeError('Invalid private key length!');
        }
        if (publicKey.byteLength !== PUBLIC_KEY_LENGTH) {
            throw new RangeError('Invalid public key length!');
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
            free(sk);
            free(pk);
            free(m);
            free(s);
            throw new Error('Signature generation failed!');
        }
    },

    async verify(publicKey, message, signature) {
        if (publicKey.byteLength !== PUBLIC_KEY_LENGTH) {
            throw new RangeError('Invalid public key length!');
        }
        if (signature.byteLength !== SIGNATURE_LENGTH) {
            throw new RangeError('Invalid signature length!');
        }
        const { verify, allocU8, free } = await methods;
        const pk = allocU8(PRIVATE_KEY_LENGTH, publicKey);
        const m = allocU8(message.byteLength, message);
        const s = allocU8(SIGNATURE_LENGTH, signature);
        const valid = verify(pk, m, message.byteLength, s);
        free(pk);
        free(m);
        free(s);
        return valid === 1 ? true : false;
    },

    async generateCompressedPublicKey(secretKey) {
        if (secretKey.byteLength !== PRIVATE_KEY_LENGTH) {
            throw new RangeError('Invalid private key length!');
        }
        const { generateCompressedPublicKey, allocU8, free } = await methods;
        const sk = allocU8(PRIVATE_KEY_LENGTH, secretKey);
        const pk = allocU8(PUBLIC_KEY_LENGTH);
        if (generateCompressedPublicKey(sk, pk)) {
            const out = pk.slice();
            free(sk);
            free(pk);
            return out;
        } else {
            free(sk);
            free(pk);
            throw new Error('Compressed public key generation failed!');
        }
    },

    async compressedSecretAgreement(secretKey, publicKey) {
        if (secretKey.byteLength !== PRIVATE_KEY_LENGTH) {
            throw new RangeError('Invalid private key length!');
        }
        if (publicKey.byteLength !== PUBLIC_KEY_LENGTH) {
            throw new RangeError('Invalid public key length!');
        }
        const { compressedSecretAgreement, allocU8, free } = await methods;
        const sk = allocU8(PRIVATE_KEY_LENGTH, secretKey);
        const pk = allocU8(PUBLIC_KEY_LENGTH, publicKey);
        const ssk = allocU8(SHARED_SECRET_LENGTH);
        if (compressedSecretAgreement(sk, pk, ssk)) {
            const out = ssk.slice();
            free(sk);
            free(pk);
            free(ssk);
            return out;
        } else {
            free(sk);
            free(pk);
            free(ssk);
            throw new Error('Compressed secret agreement failed!');
        }
    },

    async K12(input, output, outputSize, outputOffset = 0) {
        if (output.byteLength < outputSize) {
            throw new RangeError('Invalid output size!');
        }
        const { K12, allocU8, free } = await methods;
        const inp = allocU8(input.byteLength, input);
        const out = allocU8(outputSize);
        if (K12(inp, input.byteLength, out, outputSize)) {
            output.set(out.slice(), outputOffset);
            free(inp);
            free(out);
        } else {
            free(inp);
            free(out);
            throw new Error('K12 failed!');
        }
    },

    async merkleRoot(depth, index, data, siblings, root) {
        if (root.byteLength !== DIGEST_LENGTH) {
            throw new Error('Invalid root size!');
        }
        if ((siblings.byteLength / depth) !== DIGEST_LENGTH) {
            throw new Error('Invalid siblings size!');
        }
        const { merkleRoot, allocU8, free } = await methods;
        const d = allocU8(data.byteLength, data);
        const s = allocU8(siblings.byteLength, siblings);
        const r = allocU8(DIGEST_LENGTH);
        if (merkleRoot(depth, index, d, data.byteLength, s, r)) {
            root.set(r.slice());
            free(d);
            free(s);
            free(r);
        } else {
            free(d);
            free(s);
            free(r);
            throw new Error('Merkle root: K12 failed!');
        }
    },

    async verifySolution(
        dataLength,
        infoLength,
        numberOfInputNeurons,
        numberOfOutputNeurons,
        maxInputDuration,
        maxOutputDuration,
        neuronValueLimit,
        randomSeed,
        solutionThreshold,
        computorPublicKey,
        nonce,
    ) {
        if (!Number.isInteger(dataLength) || !Number.isInteger(infoLength) || !Number.isInteger(numberOfInputNeurons) || !Number.isInteger(numberOfOutputNeurons) || !Number.isInteger(maxInputDuration) || !Number.isInteger(maxOutputDuration) || (typeof neuronValueLimit !== 'bigint') || !Number.isInteger(solutionThreshold)) {
            throw new Error('Invalid mining params!');
        }
        if (randomSeed.byteLength !== DIGEST_LENGTH) {
            throw new Error('Invalid random seed size!!');
        }
        if (computorPublicKey.byteLength !== PUBLIC_KEY_LENGTH) {
            throw new Error('Invalid computor public key size!!');
        }
        if (nonce.byteLength !== NONCE_LENGTH) {
            throw new Error('Invalid nonce size!!');
        }
        const { verifySolution, allocU8, free } = await methods;
        const neuronValueLimitBytes = new Uint8Array(8);
        new DataView(neuronValueLimitBytes.buffer, neuronValueLimitBytes.byteOffset).setBigUint64(0, neuronValueLimit, true);
        const nvl = allocU8(8, neuronValueLimitBytes);
        const rs = allocU8(DIGEST_LENGTH, randomSeed);
        const pk = allocU8(PUBLIC_KEY_LENGTH, computorPublicKey);
        const n = allocU8(NONCE_LENGTH, nonce);
        const valid = verifySolution(dataLength, infoLength, numberOfInputNeurons, numberOfOutputNeurons, maxInputDuration, maxOutputDuration, nvl, rs, solutionThreshold, pk, n);
        free(nvl);
        free(rs);
        free(pk);
        free(n);
        return valid === 1 ? true : false;
    },
};

export default crypto;
