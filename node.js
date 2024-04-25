"use strict";

let crypto = require("crypto");

let sharedSecret;

function bespokeEncrypt(plaintext) {
  let initializationVector = crypto.randomBytes(16); // IV is always 8-bytes
  let encrypted = "";

  let cipher = crypto.createCipheriv(
    "aes-128-cbc",
    sharedSecret,
    initializationVector
  );
  encrypted += cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");

  return (
    toWeb64(encrypted) + ":" + toWeb64(initializationVector.toString("base64"))
  );
}

function bespokeDecrypt(parts) {
  let [encrypted, initializationVector] = parts.split(":");
  let plaintext = "";

  let cipher = crypto.createDecipheriv(
    "aes-128-cbc",
    sharedSecret,
    Buffer.from(initializationVector, "base64")
  );
  plaintext += cipher.update(encrypted, "base64", "utf8");
  plaintext += cipher.final("utf8");

  return plaintext;
}

function toWeb64(x) {
  return x.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

module.exports.bespokeEncrypt = bespokeEncrypt;
module.exports.bespokeDecrypt = bespokeDecrypt;
module.exports.init = function (_sharedSecret) {
  sharedSecret = Buffer.from(_sharedSecret, "base64");
};
