# [Cipher.js](https://github.com/therootcompany/cipher.js) for Node

```js
// Generate a 128-bit AES secret:
crypto
  .randomBytes(16)
  .toString("base64")
  .replace(/\//g, "_")
  .replace(/\+/g, "-")
  .replace(/=/g, "");
```

```js
let Cipher = require("@root/cipher");

Cipher.init("xxxxxxxxxxxxxxxxxxxxxx");

let encrypted = Cipher.bespokeEncrypt("123-45-6789");
console.info("Encrypted", encrypted);

let plaintext = Cipher.bespokeDecrypt(encrypted);
console.info("Decrypted", plaintext);
```

# LICENSE

Copyright 2021-Present Root, Inc

This Source Code Form is subject to the terms of the Mozilla \
Public License, v. 2.0. If a copy of the MPL was not distributed \
with this file, You can obtain one at \
https://mozilla.org/MPL/2.0/.
