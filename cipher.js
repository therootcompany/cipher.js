"use strict";

let Cipher = module.exports;

let Crypto = globalThis.crypto;

const IV_SIZE = 12;
const TAG_SIZE = 12;

let decoder = new TextDecoder();
let encoder = new TextEncoder();

/**
 * @param {Uint8Array} sharedSecret
 */
Cipher.create = function (sharedSecret) {
  let cipher = {};

  // https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/k6/experimental/webcrypto.d.ts#L109
  const NON_EXTRACTABLE = false;
  /** @type {"raw"}*/
  let keyFormat = "raw";
  let algoOpts = {
    name: "AES-GCM",
    tagLength: TAG_SIZE * 8,
    // additionalData: null,
  };
  /** @type {Array<"encrypt" | "decrypt" | "sign" | "verify">} */
  let keyUsages = ["encrypt", "decrypt"];
  /** @type {CryptoKey} */
  let sharedKey;
  cipher._init = async function () {
    if (sharedKey) {
      return;
    }

    sharedKey = await Crypto.subtle.importKey(
      keyFormat,
      sharedSecret,
      algoOpts,
      NON_EXTRACTABLE,
      keyUsages
    );

    return sharedKey;
  };

  /**
   * Encrypts a string and encodes it as base64urlsafe
   * @param {String} str - utf8 string
   * @returns {Promise<String>}
   */
  cipher.encryptString = async function (str) {
    let bytes = encoder.encode(str);
    let encrypted = await cipher.encrypt(bytes);

    return encrypted;
  };

  /**
   * Encrypts a string and encodes it as base64urlsafe
   * @param {String} str - utf8 string
   * @returns {Promise<Uint8Array>}
   */
  cipher.encryptStringAsBytes = async function (str) {
    let bytes = encoder.encode(str);
    let encBytes = await cipher.encryptAsBytes(bytes);

    return encBytes;
  };

  /**
   * Encrypts a byte array and encodes it as base64urlsafe
   * @param {Uint8Array} bytes
   * @param {Uint8Array} [_testIv] - for tests only, do not use
   * @returns {Promise<String>}
   */
  cipher.encrypt = async function (bytes, _testIv) {
    // let iv64 = Cipher.utils.bytesToUrlSafe(initializationVector);

    let enc = await cipher.encryptAsBytes(bytes, _testIv);
    let encUrlSafe = Cipher.utils.bytesToUrlSafe(enc);

    return encUrlSafe;
  };

  /**
   * Encrypts a byte array and encodes it as base64urlsafe
   * @param {Uint8Array} bytes
   * @param {Uint8Array} [_testIv] - for tests only, do not use
   * @returns {Promise<Uint8Array>}
   */
  cipher.encryptAsBytes = async function (bytes, _testIv) {
    await cipher._init();

    let initializationVector = new Uint8Array(IV_SIZE);
    void Crypto.getRandomValues(initializationVector);
    if (_testIv) {
      initializationVector = _testIv;
    }

    let encryptOpts = Object.assign({ iv: initializationVector }, algoOpts);
    let buffer = await Crypto.subtle.encrypt(encryptOpts, sharedKey, bytes);
    let cipherBytes = new Uint8Array(buffer);

    let len = IV_SIZE + cipherBytes.length;
    let enc = new Uint8Array(len);

    let offset = 0;
    enc.set(initializationVector, offset);

    offset += IV_SIZE;
    enc.set(cipherBytes, offset);

    return enc;
  };

  /**
   * @param {String} encUrlSafe
   * @returns {Promise<String>}
   */
  cipher.decryptToString = async function (encUrlSafe) {
    let bytes = await cipher.decrypt(encUrlSafe);
    let str = decoder.decode(bytes);

    return str;
  };

  /**
   * @param {Uint8Array} encBytes
   * @returns {Promise<String>}
   */
  cipher.decryptBytesToString = async function (encBytes) {
    let bytes = await cipher.decryptBytes(encBytes);
    let str = decoder.decode(bytes);

    return str;
  };

  /**
   * Encrypts a byte array and encodes it as base64urlsafe
   * @param {String} encUrlSafe
   * @return {Promise<Uint8Array>}
   */
  cipher.decrypt = async function (encUrlSafe) {
    let encBytes = Cipher.utils.urlSafeToBytes(encUrlSafe);
    let bytes = await cipher.decryptBytes(encBytes);

    return bytes;
  };

  /**
   * Encrypts a byte array and encodes it as base64urlsafe
   * @param {Uint8Array} encBytes
   * @return {Promise<Uint8Array>}
   */
  cipher.decryptBytes = async function (encBytes) {
    await cipher._init();

    let ivBytes = encBytes.slice(0, IV_SIZE);
    let encDataBytes = encBytes.slice(IV_SIZE);

    let decryptOpts = Object.assign({ iv: ivBytes }, algoOpts);
    let buffer = await Crypto.subtle.decrypt(
      decryptOpts,
      sharedKey,
      encDataBytes
    );

    let bytes = new Uint8Array(buffer);
    return bytes;
  };

  return cipher;
};

Cipher.utils = {};

/**
 * Replaces all + with - and all / with _ and strips all trailing =
 * @param {Base64} base64
 * @returns {Base64UrlSafe}
 */
Cipher.utils.base64ToUrlSafe = function (base64) {
  let base64url = base64.replace(/\+/g, "-");
  base64url = base64url.replace(/\//g, "_");
  base64url = base64url.replace(/=/g, "");

  return base64url;
};

/**
 * Replaces all - with + and all _ with / and adds trailing =s
 * @param {Base64UrlSafe} urlsafe
 * @returns {Base64}
 */
Cipher.utils.urlSafeToBase64 = function (urlsafe) {
  let base64 = urlsafe.replace(/-/g, "+");
  base64 = base64.replace(/_/g, "/");

  let padLen = base64.length % 4; // E: Variable 'base64' is used before being assigned.
  if (padLen > 0) {
    padLen = 4 - padLen;
    let padding = "=".repeat(padLen);
    base64 = `${base64}${padding}`;
  }

  return base64;
};

/**
 * @param {String} base64urlsafe
 * @returns {Uint8Array}
 */
Cipher.utils.urlSafeToBytes = function (base64urlsafe) {
  let base64 = Cipher.utils.urlSafeToBase64(base64urlsafe);
  let bytes = Cipher.utils.base64ToBytes(base64);

  return bytes;
};

/**
 * @param {Uint8Array} bytes
 * @returns {Base64UrlSafe} - base64urlsafe string
 */
Cipher.utils.bytesToUrlSafe = function (bytes) {
  let base64 = Cipher.utils.bytesToBase64(bytes);
  let base64urlsafe = Cipher.utils.base64ToUrlSafe(base64);

  return base64urlsafe;
};

/**
 * @param {String} base64
 * @returns {Uint8Array}
 */
Cipher.utils.base64ToBytes = function (base64) {
  let binaryString = globalThis.atob(base64);
  let bytes = new Uint8Array(binaryString.length);

  for (let i = 0; i < binaryString.length; i += 1) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes;
};

/**
 * @param {Uint8Array} bytes
 * @returns {Base64} - base64 string
 */
Cipher.utils.bytesToBase64 = function (bytes) {
  let binary = "";

  for (let b of bytes) {
    binary += String.fromCharCode(b);
  }

  let base64 = globalThis.btoa(binary);
  return base64;
};

/**
 * @param {String} hex
 * @returns {Uint8Array}
 */
Cipher.utils.hexToBytes = function (hex) {
  let bufLen = hex.length / 2;
  let bytes = new Uint8Array(bufLen);

  let i = 0;
  let index = 0;
  let lastIndex = hex.length - 2;
  for (;;) {
    if (i > lastIndex) {
      break;
    }
    let h = hex.slice(i, i + 2);
    let b = parseInt(h, 16);
    bytes[index] = b;
    i += 2;
    index += 1;
  }

  return bytes;
};

/**
 * @param {Uint8Array} bytes
 * @returs {Hex} - hex string
 */
Cipher.utils.bytesToHex = function (bytes) {
  /** @type {Array<String>} */
  let hex = [];

  for (let b of bytes) {
    let h = b.toString(16).padStart(2, "0");
    hex.push(h);
  }

  return hex.join("");
};

/** @typedef {String} Base64 */
/** @typedef {String} Base64UrlSafe */
/** @typedef {String} Hex */
