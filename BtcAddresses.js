// app.js - A back-end Node.js app that exposes an API 
// to generate BIP39 mnemonics, convert them to seeds, and derive Bitcoin addresses.
const express = require('express');
const crypto = require('crypto');
const ENGLISH_WORDLIST = require('./wordlists/english.js');
// Helper functions adapted for Node.js (using crypto module instead of browser dependencies)
function bytesToBinary(bytes) {
    return bytes.map((x) => x.toString(2).padStart(8, '0')).join('');
}
function binaryToByte(binary) {
    return parseInt(binary, 2);
}
function deriveChecksumBits(entropyBuffer) {
    const ENT = entropyBuffer.length * 8;
    const CS = ENT / 32;
    const hash = crypto.createHash('sha256').update(entropyBuffer).digest();
    return bytesToBinary(Array.from(hash)).slice(0, CS);
}
function entropyToMnemonic(entropy, wordlist = ENGLISH_WORDLIST) {
    if (!Buffer.isBuffer(entropy)) {
        entropy = Buffer.from(entropy);
    }
    if (entropy.length < 16) {
        throw new TypeError('entropy too short');
    }
    if (entropy.length > 32) {
        throw new TypeError('entropy too long');
    }
    if (entropy.length % 4 !== 0) {
        throw new TypeError('invalid entropy');
    }
    const entropyBits = bytesToBinary(Array.from(entropy));
    const checksumBits = deriveChecksumBits(entropy);
    const bits = entropyBits + checksumBits;
    const chunks = bits.match(/(.{1,11})/g);
    const words = chunks.map((binary) => {
        const index = binaryToByte(binary);
        return wordlist[index];
    });
    return words.join(' ');
}
function generateMnemonic(strength = 128, wordlist = ENGLISH_WORDLIST) {
    if (strength % 32 !== 0) {
        throw new TypeError('invalid entropy');
    }
    const entropy = crypto.randomBytes(strength / 8);
    return entropyToMnemonic(entropy, wordlist);
}
function validateMnemonic(mnemonic, wordlist = ENGLISH_WORDLIST) {
    try {
        mnemonicToEntropy(mnemonic, wordlist);
    } catch (e) {
        return false;
    }
    return true;
}
function mnemonicToEntropy(mnemonic, wordlist = ENGLISH_WORDLIST) {
    const words = mnemonic.split(' ');
    if (words.length % 3 !== 0) {
        throw new Error('invalid mnemonic');
    }
    const bits = words.map((word) => {
        const index = wordlist.indexOf(word);
        if (index === -1) {
            throw new Error('invalid mnemonic');
        }
        return index.toString(2).padStart(11, '0');
    }).join('');
    const dividerIndex = Math.floor(bits.length / 33) * 32;
    const entropyBits = bits.slice(0, dividerIndex);
    const checksumBits = bits.slice(dividerIndex);
    const entropy = Buffer.from(entropyBits.match(/(.{1,8})/g).map(binaryToByte));
    const newChecksum = deriveChecksumBits(entropy);
    if (newChecksum !== checksumBits) {
        throw new Error('invalid checksum');
    }
    return entropy;
}
function mnemonicToSeedSync(mnemonic, passphrase = '') {
    const mnemonicBuffer = Buffer.from(mnemonic.normalize('NFKD'), 'utf8');
    const saltBuffer = Buffer.from(`mnemonic${passphrase.normalize('NFKD')}`, 'utf8');
    return crypto.pbkdf2Sync(mnemonicBuffer, saltBuffer, 2048, 64, 'sha512');
}
// BIP32 and Address Generation Helpers
const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
function uintToNum(uint32be) {
    return BigInt('0x' + uint32be.toString('hex'));
}
function numTo32byteUint(num) {
    let hex = num.toString(16);
    hex = hex.padStart(64, '0');
    return Buffer.from(hex, 'hex');
}
function uint32leBuffer(i) {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(i, 0);
    return b;
}
function getCompressedPubkey(privKey) {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(privKey);
    const pubHex = ecdh.getPublicKey('hex', 'compressed');
    return Buffer.from(pubHex, 'hex');
}
function hmacSha512(key, data) {
    const hmac = crypto.createHmac('sha512', key);
    hmac.update(data);
    return hmac.digest();
}
function seedToMaster(seed) {
    const hmac = crypto.createHmac('sha512', Buffer.from('Bitcoin seed'));
    hmac.update(seed);
    const I = hmac.digest();
    let ilNum = uintToNum(I.slice(0, 32));
    if (ilNum === 0n || ilNum >= N) {
        throw new Error('Invalid master key');
    }
    const masterPriv = numTo32byteUint(ilNum);
    const masterChain = I.slice(32);
    return { priv: masterPriv, chain: masterChain };
}
function deriveChild(parent, index, hardened) {
    let data;
    if (hardened) {
        data = Buffer.concat([Buffer.from([0x00]), parent.priv, uint32leBuffer(index)]);
    } else {
        const pub = getCompressedPubkey(parent.priv);
        data = Buffer.concat([pub, uint32leBuffer(index)]);
    }
    const I = hmacSha512(parent.chain, data);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    let ilNum = uintToNum(IL);
    if (ilNum >= N) {
        throw new Error('Invalid child key');
    }
    let childNum = (uintToNum(parent.priv) + ilNum) % N;
    if (childNum === 0n) {
        throw new Error('Invalid child key');
    }
    const childPriv = numTo32byteUint(childNum);
    return { priv: childPriv, chain: IR };
}
function derivePath(seed, path) {
    // For Bitcoin: m/44'/0'/0'/0/0
    const indices = [2147483692, 2147483648, 2147483648, 0, 0]; // 44', 0', 0', 0, 0
    const hardeneds = [true, true, true, false, false];
    let current = seedToMaster(seed);
    for (let i = 0; i < indices.length; i++) {
        current = deriveChild(current, indices[i], hardeneds[i]);
    }
    return current.priv;
}
function privateKeyToAddress(privKey) {
    const pubKey = getCompressedPubkey(privKey);
    const sha256Hash = crypto.createHash('sha256').update(pubKey).digest();
    const ripemd160Hash = crypto.createHash('ripemd160').update(sha256Hash).digest();
    const versionedPayload = Buffer.concat([Buffer.from([0x00]), ripemd160Hash]);
    const checksum = crypto.createHash('sha256').update(crypto.createHash('sha256').update(versionedPayload).digest()).digest().slice(0, 4);
    const fullPayload = Buffer.concat([versionedPayload, checksum]);
    const hexPayload = fullPayload.toString('hex');
    return encode_b58(hexPayload);
}
function encode_b58(hex_number) {
    // Set of base58 chars (Note: there is no '0','O','I' or 'l').
    const base58 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
    //Take input string of hexadecimal bytes and convert it to a base 10
    //decimal number. BigInt needed as regular JS numbers don't represent enough significant digits.
    var num = BigInt('0x' + hex_number);
    //Our very large number will be repeatedly divided by 58.
    const fifty8 = BigInt(58);
    //The remainder of this division will be a number (0-57).
    var remainder;
    //Each remainder's value maps to a character in our base58 array, and
    //the string of these characters becomes our Base58 encoded output.
    var b58_encoded_buffer = '';
    //We move from: Hex Bytes -> Decimal Number -> Base58 Encoded string.
    //To move through each place value of a base58 number, we continue to
    //divide by 58, until the integer number rounds down to 0.
    while (num > 0) {
        //The modulus operator returns our remainder, which depends on
        //the least significant digit in our BigInt converted input.
        //For example: if we were doing modulo 2 division, all odd
        //numbers - regardless of how long they are - would return a
        //remainder of 1, because the least significant digit is odd.
        remainder = num % fifty8;
        //Thus, we're encoding the right most (lowest place value)
        //digits first, and so each subsequently encoded character
        //needs to be added to the left of our encoded buffer
        //so that the beginning & end of our input string/bytes aligns
        //with the beginning & end of our Base58 encoded output.
        b58_encoded_buffer = base58[Number(remainder)] + b58_encoded_buffer;
        //Dividing by 58 gives us our quotient (rounded down to the
        //nearest integer), and moves us over one base58 place value,
        //ready for the next round of b58 division/mapping/encoding.
        num = num / BigInt(58);
    }
    //When we convert our byte-based hex input into a base 10 number, we
    //lose the leading zero bytes in the converted decimal number.
    //For example, if our hex input converted into the decimal number
    //000017, this number would be reduced automatically to 17 in base10,
    //and so we'd lose the leading zeros, which aren't important
    //when doing base 10 math, but are important in preserving the
    //information held in our original input value. So, in order to not
    //lose the leading zeros, we count them, and then prepend them (as
    //1's, which is their corresponding base58 value) to the beginning
    //of our Base58 encoded output string.
    while (hex_number.match(/^00/)) {
        //For each leading zero byte, add a '1' to the encoded output.
        b58_encoded_buffer = '1' + b58_encoded_buffer;
        //And remove the leading zero byte, and test for another.
        hex_number = hex_number.substring(2);
    }
    return b58_encoded_buffer;
}
// Express app
const app = express();
const port = 3000;
app.use(express.json());
app.get('/generate', (req, res) => {
    const strength = parseInt(req.query.strength) || 128;
    try {
        const mnemonic = generateMnemonic(strength);
        res.json({ mnemonic });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});
app.post('/validate', (req, res) => {
    const { mnemonic } = req.body;
    if (!mnemonic) {
        return res.status(400).json({ error: 'mnemonic required' });
    }
    const valid = validateMnemonic(mnemonic);
    res.json({ valid });
});
app.post('/to-seed', (req, res) => {
    const { mnemonic, passphrase } = req.body;
    if (!mnemonic) {
        return res.status(400).json({ error: 'mnemonic required' });
    }
    try {
        const seed = mnemonicToSeedSync(mnemonic, passphrase || '');
        res.json({ seed: seed.toString('hex') });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});
app.post('/to-address', (req, res) => {
    const { mnemonic, passphrase = '' } = req.body;
    if (!mnemonic) {
        return res.status(400).json({ error: 'mnemonic required' });
    }
    try {
        const seed = mnemonicToSeedSync(mnemonic, passphrase);
        const privKey = derivePath(seed, "m/44'/0'/0'/0/0");
        const address = privateKeyToAddress(privKey);
        res.json({ address });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});
app.listen(port, () => {
    console.log(`BIP39 back-end app listening at http://localhost:${port}`);
});
// To run: node app.js
// Example usage: 
// GET /generate?strength=256 for a 24-word mnemonic
// POST /validate with body { "mnemonic": "your words here" }
// POST /to-seed with body { "mnemonic": "your words here", "passphrase": "optional" }
// POST /to-address with body { "mnemonic": "your words here", "passphrase": "optional" } for Bitcoin P2PKH address at m/44'/0'/0'/0/0
// This adapts the original browser-based JavaScript code to run on Node.js, using built-in crypto for 
// randomness, hashing, and PBKDF2, removing any browser-specific dependencies. For other languages, 
// you can add similar wordlists.