"use strict";

require("dotenv").config();

let Assert = require("node:assert/strict");
let Crypto = globalThis.crypto;

let Cipher = require("../cipher.js");

async function test() {
  {
    // 128-bit (16-byte)
    let secret128 = new Uint8Array([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x90, 0xa0, 0xb0,
      0xc0, 0xd0, 0xe0, 0xf0,
    ]);
    let iv128 = new Uint8Array([
      0x01, 0x00, 0x90, 0xa0, 0x05, 0x06, 0x07, 0x08, 0xb0, 0xc0, 0xd0, 0x0f,
      0xe0, 0x02, 0x03, 0x04,
    ]);
    let exp64 = "AQCQoAUGBwiwwNAP4AIDBLLnH3xgsW4DmAlTqEw3nDI";
    let enc64 = await testOne(secret128, iv128);

    Assert.equal(enc64, exp64);
  }

  {
    // 256-bit (32-byte)
    let secret256 = new Uint8Array([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x90, 0xa0, 0xb0,
      0xc0, 0xd0, 0xe0, 0xf0, 0x00, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]);
    // iv is always 16 bytes
    let iv128 = new Uint8Array([
      0x01, 0x00, 0x90, 0xa0, 0x05, 0x06, 0x07, 0x08, 0xb0, 0xc0, 0xd0, 0x0f,
      0xe0, 0x02, 0x03, 0x04,
    ]);
    let exp64 = "AQCQoAUGBwiwwNAP4AIDBAMOdOmrmBWpKmHe8IDqnJU";
    let enc64 = await testOne(secret256, iv128);
    Assert.equal(enc64, exp64);
  }

  let sharedSecret = new Uint8Array(24);
  for (let i = 1; i < 1000; i += 1) {
    void Crypto.getRandomValues(sharedSecret);
    void (await testOne(sharedSecret));
  }
}

async function testOne(sharedSecret, testIv) {
  let cipher = Cipher.create(sharedSecret);

  let clearText = "123-45-6789";
  let encoder = new TextEncoder();
  let clearBytes = encoder.encode(clearText);
  // let encrypted = await cipher.encryptString(clearText);
  let encrypted = await cipher.encrypt(clearBytes, testIv);
  console.info("Encrypted", encrypted);

  let decText = await cipher.decryptToString(encrypted);
  console.info("Decrypted", clearText);

  Assert.equal(decText, clearText);

  return encrypted;
}

if (require.main === module) {
  test()
    .then(function () {
      console.info(`PASS`);
    })
    .catch(function (err) {
      console.error(`FAIL`);
      console.error(err);
      process.exit(1);
    });
}
