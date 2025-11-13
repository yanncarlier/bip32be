// app.js - A back-end Node.js app that exposes an API 
// to generate BIP39 mnemonics and convert them to seeds.
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
app.listen(port, () => {
    console.log(`BIP39 back-end app listening at http://localhost:${port}`);
});
// To run: node app.js
// Example usage: GET /generate?strength=256 for a 24-word mnemonic
// POST /validate with body { "mnemonic": "your words here" }
// POST /to-seed with body { "mnemonic": "your words here", "passphrase": "optional" }
// This adapts the original browser-based JavaScript code to run on Node.js, using built-in crypto for 
// randomness, hashing, and PBKDF2, removing any browser-specific dependencies. For other languages, 
// you can add similar wordlists.