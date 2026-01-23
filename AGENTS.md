# AGENTS.md - Development Guidelines for bip32be

This document provides comprehensive guidelines for coding agents working on the bip32be project, a Node.js API server for BIP39 mnemonic generation and BIP32 Bitcoin address derivation.

## Build, Lint, and Test Commands

### Development Setup
```bash
# Install dependencies
npm install

# Start development server
npm start
# or directly with node
node BtcAddresses.js
```

### Testing
Currently no test framework is configured. Recommended setup:

```bash
# Install testing dependencies (add to package.json)
npm install --save-dev jest supertest

# Run all tests
npm test

# Run a specific test file
npm test -- tests/mnemonic.test.js

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

### Linting and Code Quality
Currently no linting is configured. Recommended setup:

```bash
# Install ESLint and Prettier
npm install --save-dev eslint prettier eslint-config-prettier eslint-plugin-node

# Lint code
npm run lint

# Fix linting issues automatically
npm run lint:fix

# Format code
npm run format

# Check formatting
npm run format:check
```

### Type Checking (Future Enhancement)
For future TypeScript migration:

```bash
# Install TypeScript
npm install --save-dev typescript @types/node @types/express

# Type check
npm run typecheck
```

## Code Style Guidelines

### File Organization
- Use `.js` extension for all JavaScript files
- Place main application files in the root directory
- Use `wordlists/` subdirectory for word list data
- Group related functions together in logical modules

### Import/Export Conventions
Use CommonJS modules consistently:

```javascript
// Good: Clear, descriptive imports
const crypto = require('crypto');
const express = require('express');
const ENGLISH_WORDLIST = require('./wordlists/english.js');

// Good: Named exports for utilities
module.exports = {
    generateMnemonic,
    validateMnemonic,
    mnemonicToSeedSync
};
```

### Naming Conventions

#### Variables and Functions
- Use `camelCase` for variables, functions, and method names
- Use descriptive, meaningful names that explain purpose
- For crypto-related variables, use full words over abbreviations

```javascript
// Good
function generateMnemonic(strength = 128, wordlist = ENGLISH_WORDLIST) {
    const entropy = crypto.randomBytes(strength / 8);
    const checksumBits = deriveChecksumBits(entropy);
    // ...
}

// Avoid
function genMnemo(s = 128, wl = ENGLISH_WORDLIST) {
    const e = crypto.randomBytes(s / 8);
    const cs = deriveChecksumBits(e);
    // ...
}
```

#### Constants
- Use `UPPER_CASE_WITH_UNDERSCORES` for mathematical constants and configuration
- Use `camelCase` for computed constants

```javascript
// Good
const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const ENGLISH_WORDLIST = require('./wordlists/english.js');
const defaultStrength = 128;
```

### Code Formatting

#### Indentation
- Use 4 spaces for indentation (consistent with existing codebase)
- Never mix tabs and spaces

#### Line Length
- Keep lines under 100 characters when possible
- Break long lines at logical points (after operators, commas)

```javascript
// Good: Broken at logical points
const versionedPayload = Buffer.concat([
    Buffer.from([0x00]),
    ripemd160Hash
]);
```

#### Spacing
- One space around binary operators: `a + b`, `x === y`
- No space after function names: `function foo()` not `function foo ()`
- One space after commas: `func(a, b, c)` not `func(a,b,c)`
- One space after colons in object literals: `{key: value}`

### Function Structure

#### Function Organization
- Group related functions together
- Place helper functions before main application logic
- Export public API functions at the end

#### Parameter Defaults
- Use default parameters for optional values
- Place required parameters first, optional last

```javascript
// Good
function mnemonicToSeedSync(mnemonic, passphrase = '') {
    // implementation
}
```

#### Function Comments
- Add JSDoc-style comments for all exported functions
- Include parameter descriptions and return types

```javascript
/**
 * Converts a BIP39 mnemonic to a seed using PBKDF2
 * @param {string} mnemonic - Space-separated BIP39 words
 * @param {string} passphrase - Optional passphrase for additional security
 * @returns {Buffer} 64-byte seed buffer
 */
function mnemonicToSeedSync(mnemonic, passphrase = '') {
    // implementation
}
```

### Error Handling

#### Exception Patterns
- Use `TypeError` for invalid input types or values
- Use `Error` for general validation failures
- Throw errors immediately when validation fails

```javascript
// Good: Clear error messages and appropriate error types
if (entropy.length < 16) {
    throw new TypeError('entropy too short');
}
if (index === -1) {
    throw new Error('invalid mnemonic');
}
```

#### API Error Responses
- Return structured JSON error responses
- Include descriptive error messages
- Use appropriate HTTP status codes

```javascript
// Good: Consistent error response format
app.post('/validate', (req, res) => {
    const { mnemonic } = req.body;
    if (!mnemonic) {
        return res.status(400).json({ error: 'mnemonic required' });
    }
    // ... validation logic
});
```

### Security Considerations

#### Cryptographic Operations
- Use Node.js built-in `crypto` module exclusively
- Never implement custom cryptographic functions
- Validate all inputs before cryptographic operations
- Use constant-time comparisons where applicable

#### Input Validation
- Validate mnemonic format before processing
- Check entropy length and divisibility requirements
- Sanitize and validate all user inputs

```javascript
// Good: Comprehensive input validation
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
    // ... rest of function
}
```

### Buffer and BigInt Handling

#### Buffer Operations
- Use `Buffer.alloc()` for creating new buffers
- Use `Buffer.concat()` for combining buffers
- Specify encoding explicitly when converting to/from strings

```javascript
// Good: Explicit encoding and proper buffer creation
const mnemonicBuffer = Buffer.from(mnemonic.normalize('NFKD'), 'utf8');
const b = Buffer.alloc(4);
b.writeUInt32LE(i, 0);
```

#### BigInt Usage
- Use `BigInt` for large number operations (BIP32 mathematics)
- Convert between `BigInt` and `Buffer` using utility functions
- Use `n` suffix for BigInt literals

```javascript
// Good: Clear BigInt usage
const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
let childNum = (uintToNum(parent.priv) + ilNum) % N;
```

### Testing Guidelines

#### Test Structure
- Test files should mirror source file structure: `mnemonic.test.js`
- Use descriptive test names that explain the behavior being tested
- Test both success and failure cases

#### Test Categories
- Unit tests for utility functions (entropyToMnemonic, validateMnemonic)
- Integration tests for API endpoints
- Property-based tests for cryptographic functions (when available)

### Performance Considerations

#### Cryptographic Operations
- Use synchronous crypto operations for API responses
- Cache expensive computations where appropriate
- Avoid unnecessary buffer allocations

#### Memory Management
- Use streaming for large data processing (future enhancement)
- Clean up resources in error paths
- Monitor memory usage in production

## Development Workflow

1. **Setup**: Install dependencies and verify the application runs
2. **Development**: Make changes following the style guidelines above
3. **Testing**: Write tests for new functionality before committing
4. **Linting**: Run linters and fix any issues
5. **Review**: Ensure code follows all guidelines in this document

## Future Enhancements

- Consider migrating to TypeScript for better type safety
- Add comprehensive test suite with Jest
- Implement ESLint and Prettier for code quality
- Add API documentation with OpenAPI/Swagger
- Consider adding rate limiting and input sanitization middleware

---

This document should be updated as the codebase evolves and new patterns emerge.</content>
<parameter name="filePath">/home/y/MY_PROJECTS/Wallets/bip32be/AGENTS.md