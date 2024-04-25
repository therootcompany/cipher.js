# [Cipher.js](https://github.com/therootcompany/cipher.js) for Bun, Node, and Browsers

```js
// Generate a 128-bit, 192-bit, or 256-bit AES secret:
let secretBytes = new Uint8Array(16); // or 24, or 32
crypto.getRandomValues(secretBytes);

let secretHex = Cipher.utils.bytesTohex(secretBytes);
```

```js
let Cipher = require("@root/cipher");

let sharedSecret = Cipher.utils.hexToBytes(secretHex);
let cipher = Cipher.create(sharedSecret);

let plain = "123-45-6789";
let encBase64UrlSafe = cipher.encryptString(plain);
console.info("Encrypted", encBase64UrlSafe);

let original = Cipher.decryptToString(encBase64UrlSafe);
console.info("Decrypted", original === plain, original);
```

## Usage

```js
let cipher = Cipher.create(keyBytes);

let encString = await cipher.encrypt(payloadBytes);
let encString = cipher.encryptString(payloadString);

let decBytes = cipher.decrypt(encString);
let decString = cipher.decryptToString(encString);
```

```sh
let hex = Cipher.utils.bytesToHex(bytes);
let bytes = Cipher.utils.hexToBytes(hex);

let base64 = Cipher.utils.bytesToBase64(bytes);
let bytes = Cipher.utils.base64ToBytes(base64);

let base64urlsafe = Cipher.utils.bytesToUrlSafe(bytes);
let bytes = Cipher.utils.urlSafeToBytes(base64urlsafe);
```

## API

```text
Cipher.create(keyBytes)             => cipher instance

cipher.encrypt(bytes)               => Promise<encrypted>
cipher.encryptString(string)        => Promise<encrypted>

cipher.decrypt(encrypted)           => Promise<bytes>
cipher.decryptToString(encrypted)   => Promise<string>
```

```text
Cipher.utils.bytesToHex(bytes)      => hexString
Cipher.utils.hexToBytes(hex)        => bytes

Cipher.utils.bytesToBase64(bytes)   => base64
Cipher.utils.base64ToBytes(base64)  => bytes

Cipher.utils.bytesToUrlSafe(bytes)  => url-safe base64 string
Cipher.utils.urlSafeToBytes(url64)  => bytes
```

To swap between the string and byte encrypted form

```text
Cipher.utils.encryptedToBytes(encString)
Cipher.utils.bytesToEncrypted(encString)
```

# LICENSE

Copyright 2021-Present Root, Inc

This Source Code Form is subject to the terms of the Mozilla \
Public License, v. 2.0. If a copy of the MPL was not distributed \
with this file, You can obtain one at \
https://mozilla.org/MPL/2.0/.
