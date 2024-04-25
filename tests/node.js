"use strict";

let Crypto = require("crypto");
let Cipher = require("../node.js");

if (require.main === module) {
  require("dotenv").config();

  // generate a 128-bit AES secret:
  // crypto.randomBytes(16).toString('base64').replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '');

  let sharedSecret;
  if (process.env.AES_SECRET) {
    sharedSecret = Buffer.from(process.env.AES_SECRET, "base64");
  } else {
    console.warn("[WARN] generating random key for testing");
    sharedSecret = Crypto.randomBytes(16);
  }
  Cipher.init(sharedSecret);

  let encrypted = Cipher.bespokeEncrypt("123-45-6789");
  console.info("Encrypted", encrypted);

  let plaintext = Cipher.bespokeDecrypt(encrypted);
  console.info("Decrypted", plaintext);
}
