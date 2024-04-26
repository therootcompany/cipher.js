# [Cipher.js](https://github.com/therootcompany/cipher.js) for Bun, Node, and Browsers

Because you don't have to be an expert to _use_ cryptography!

- Keys can be 128-, 192-, or 256-bit (16, 19, or 24 bytes)
- Plain input can be raw `Uint8Array`s or (UTF-8) `String`s
- Encrypted output can be `Base64UrlSafe` Strings, or raw `Uint8Array`s

## Table of Contents

0. Example
1. Generate a Key
2. Initialize the Cipher (Codec)
3. Encrypt (Cipher) Data
4. Decrypt (Decipher) Data
5. Convert between Bytes, Hex, Base64, and URL-Safe Base64
6. API
7. Implementation Details

## Example

Encrypt and Decrypt with AES-GCM.

```js
let Cipher = require("@root/cipher");

let cipher = Cipher.create(sharedSecret);

let plainBytes = [0xde, 0xad, 0xbe, 0xef];
let encBase64UrlSafe = cipher.encrypt(plainBytes);

let originalBytes = Cipher.decrypt(encBase64UrlSafe);
```

## Usage

Copy-and-Paste Snippets for the Masses

### 1. Generate a Key

```js
// Generate a 128-bit, 192-bit, or 256-bit AES secret:
let secretBytes = new Uint8Array(16); // or 24, or 32
crypto.getRandomValues(secretBytes);

let secretHex = Cipher.utils.bytesTohex(secretBytes);
```

### 2. Initialize the Cipher (Codec)

```js
let secretHex = process.env.APP_SECRET_KEY;

let secretBytes = Cipher.utils.hexToBytes(secretHex);
let cipher = Cipher.create(sharedSecret);
```

### 3. Encrypt (Cipher) Data

#### Plain Bytes => Encrypted Base64UrlSafe

```sh
let plainBytes = [0xde, 0xad, 0xbe, 0xef];
let encBase64UrlSafe = cipher.encrypt(plainBytes);
console.info("Encrypted (URL-Safe Base64)", encBase64UrlSafe);
```

#### Plain String => Encrypted Base64UrlSafe

```sh
let plainText = "123-45-6789";
let encBase64UrlSafe = cipher.encryptString(plainText);
console.info("Encrypted (URL-Safe Base64)", encBase64UrlSafe);
```

#### Plain Bytes => Encrypted Bytes

```sh
let plainBytes = [0xde, 0xad, 0xbe, 0xef];
let encBytes = cipher.encryptAsBytes(plainBytes);
console.info("Encrypted (Bytes)", encBytes);
```

#### Plain String => Encrypted Bytes

```sh
let plainText = "123-45-6789";
let encBytes = cipher.encryptStringAsBytes(plainText);
console.info("Encrypted (Bytes)", encBytes);
```

### 4. Decrypt (Decipher) Data

#### Encrypted String => Plain Bytes

```sh
let bytes = cipher.decrypt(encBase64UrlSafe);
console.info("Plain (Bytes)", bytes);
```

#### Encrypted Bytes => Plain Bytes

```sh
let bytes = cipher.decryptBytes(encBytes);
console.info("Plain (Bytes)", bytes);
```

#### Encrypted String => Plain String

```sh
let text = cipher.decryptToString(encBase64UrlSafe);
console.info("Plain (Text)", text);
```

#### Encrypted Bytes => Plain String

```sh
let text = cipher.decryptBytesToString(encBytes);
console.info("Plain (Text)", text);
```

### 5. Convert between Bytes, Hex, Base64, and URL-Safe Base64

Doing what `Uint8Array` should do, but doesn't.

#### Bytes <=> Hex

```sh
let hex = Cipher.utils.bytesToHex(bytes);
let bytes = Cipher.utils.hexToBytes(hex);
```

#### Bytes <=> Base64

```js
let base64 = Cipher.utils.bytesToBase64(bytes);
let bytes = Cipher.utils.base64ToBytes(base64);
```

#### Bytes <=> URL-Safe Base64

```sh
let base64urlsafe = Cipher.utils.bytesToUrlSafe(bytes);
let bytes = Cipher.utils.urlSafeToBytes(base64urlsafe);
```

## API

```text
Cipher.create(keyBytes)                => cipher instance

cipher.encrypt(bytes)                  => Promise<Base64UrlSafe>
cipher.encryptString(string)           => Promise<Base64UrlSafe>

cipher.encryptAsBytes(bytes)           => Promise<Uint8Array>
cipher.encryptStringAsBytes(string)    => Promise<Uint8Array>

cipher.decrypt(encrypted)              => Promise<Uint8Array>
cipher.decryptToString(encrypted)      => Promise<Base64UrlSafe>

cipher.decryptBytes(encBytes)          => Promise<Uint8Array>
cipher.decryptBytesToString(encBytes)  => Promise<Base64UrlSafe>
```

```text
Cipher.utils.bytesToHex(bytes)         => hex string
Cipher.utils.hexToBytes(hex)           => bytes

Cipher.utils.bytesToBase64(bytes)      => base64
Cipher.utils.base64ToBytes(base64)     => bytes

Cipher.utils.bytesToUrlSafe(bytes)     => url-safe base64 string
Cipher.utils.urlSafeToBytes(url64)     => bytes
```

## Implementation Details

The _Initialization Vector_ (_IV_) is a _salt_ that prevents known-plaintext
attacks - meaning that if you encrypt the same message with the same key twice,
you get a different encrypted output.

The first 12-bytes (96-bits) are for the _IV_. The following bytes are the data
and the _Tag_.

If the data is somehow corrupted or truncated, but the first bytes are intact,
it may be possible to use the IV to restore some of the partial data (though
_Tag_ verification will likely fail).

# LICENSE

Copyright 2021-Present Root, Inc

This Source Code Form is subject to the terms of the Mozilla \
Public License, v. 2.0. If a copy of the MPL was not distributed \
with this file, You can obtain one at \
https://mozilla.org/MPL/2.0/.
