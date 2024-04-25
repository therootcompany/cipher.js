# Cipher.js for Node

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
