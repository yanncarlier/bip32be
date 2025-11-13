

````
/usr/local/bin/node ./mnemonic_seed.js  

````

## Testing the BIP39 API with curl

Assuming the app is running on http://localhost:3000, here are curl commands to test each endpoint. These are Linux-compatible (curl is pre-installed on most distros).

1. ### Generate a Mnemonic (GET /generate)

  This generates a 24-word mnemonic (256-bit strength). You can change the strength query param (must be 128, 160, 192, 224, or 256).

````
curl -X GET "http://localhost:3000/generate?strength=256"
````

2. ### Validate a Mnemonic (POST /validate)

  Replace "your mnemonic here" with a space-separated list of words (e.g., from the generate endpoint).

````
curl -X POST "http://localhost:3000/validate" \
     -H "Content-Type: application/json" \
     -d '{"mnemonic": "your mnemonic here"}'
````
````
{"valid":false}
````

3. ### Convert Mnemonic to Seed (POST /to-seed)

````
curl -X POST "http://localhost:3000/to-seed" \
     -H "Content-Type: application/json" \
     -d '{"mnemonic": "your mnemonic here", "passphrase": ""}'
````

4. ### Derive Bitcoin Address (POST /to-address)This derives a P2PKH address at path m/44'/0'/0'/0/0.

````
curl -X POST "http://localhost:3000/to-address" \
     -H "Content-Type: application/json" \
     -d '{"mnemonic": "your mnemonic here", "passphrase": ""}'
````






````

````











