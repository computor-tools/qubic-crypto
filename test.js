import crypto from './index.js';

const test = async function () {
    const equal = function (a, b) {
        if (a.byteLength  !== b.byteLength) {
            return false;
        }
        for (let i = 0; i < a.byteLength; i++) {
            if (a[i] !== b[i]) {
                return false;
            }
        }
        return true;
    }

    const exp = {
        pk: Uint8Array.from([
            250,  81,  48,  79, 222,  52,  19, 148,
             73,   89, 140, 90,   7, 247, 102,   1,
            179, 163, 214, 186, 194,  32, 108, 252,
            229,   8, 185,  34,   1,  10, 197, 162
        ]),
        s:  Uint8Array.from([
            172, 189, 236, 216,  25, 163, 118,  27,  70,  58, 247,
             65, 184, 149, 166,  71,  81,  28, 153, 175, 177,  71,
            181, 166,   8, 228,   6,  18, 246,  83,   8,  86, 160,
            149,  69,  25,  82,  75, 192,  29,  95, 166, 179,   8,
            220,  40,  77, 130, 109, 144,  64, 124, 151, 181,  41,
            232, 119,  97,  67, 132, 114,   7,   3,   0
        ]),
        d: Uint8Array.from([
             92, 200, 181,  38, 183, 148, 163, 142,
            176, 162, 175, 236, 212, 167, 178, 149,
            197, 142,  53, 161, 223,  42, 243,   3,
             80,  93, 134, 113,  69,  74, 200, 239
        ]),
    };

    const sk = new Uint8Array(crypto.PRIVATE_KEY_LENGTH).fill(1);
    const pk = await crypto.generatePublicKey(sk);
    const testPk = equal(pk, exp.pk) && pk.byteLength === crypto.PUBLIC_KEY_LENGTH
    console.log('Public key:', testPk ? 'OK' : 'NOT OK');

    const m = new Uint8Array(138).fill(2);
    const s = await crypto.sign(sk, pk, m);
    const testSig = equal(s, exp.s) && s.byteLength === crypto.SIGNATURE_LENGTH;
    console.log('Signature:', testSig ? 'OK' : 'NOT OK');
    const s2 = s.slice();
    s2[10]++;
    const testVer = (await crypto.verify(pk, m, s) && !(await crypto.verify(pk, m, s2)));
    console.log('Verification:', testVer ? 'OK' : 'NOT_OK');

    const d = new Uint8Array(crypto.DIGEST_LENGTH).fill(0);
    await crypto.K12(m, d, crypto.DIGEST_LENGTH);
    const testK12 = equal(d, exp.d) && d.byteLength === crypto.DIGEST_LENGTH;
    console.log('K12:', testK12 ? 'OK' : 'NOT OK');

    if (!(testPk && testSig && testVer && testK12)) {
        console.log('Test failed!');
        process.exit(1);
    }

    const t0 = performance.now();
    for (let i = 0; i < 451 * 10; i++) {
        const sk = new Uint8Array(crypto.PRIVATE_KEY_LENGTH).fill(1);
        const skv = new DataView(sk.buffer, sk.byteOffset);
        skv.setUint32(0, i, true);
        const pk = await crypto.generatePublicKey(sk);
        const m = new Uint8Array(8 + 8 + 16 + 6 * crypto.DIGEST_LENGTH + 2 * crypto.DIGEST_LENGTH).fill(2);
        const d = new Uint8Array(crypto.DIGEST_LENGTH);
        await crypto.K12(m, d, crypto.DIGEST_LENGTH);
        const s = await crypto.sign(sk, pk, d);
        await crypto.verify(pk, d, s);
    }
    console.log(`bench (10*451 sign/verify): ${(performance.now() - t0).toFixed(0)}ms`);

    process.exit(0);
};

test();
