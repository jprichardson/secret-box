'use strict'
const assert = require('assert')
const crypto = require('crypto')
const scrypt = require('scryptsy')
const vstruct = require('varstruct')

// http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf 8.2.2 RBG-based Construction (about initialization vectors)
// always 12, any other value will error, not sure why it won't allow higher... probably concat with freefield?
const IV_LEN_BYTES = 12

// must always be 16 for the time being.
const SALT_LEN_BYTES = 16

const struct = vstruct([
  { name: 'version', type: vstruct.UInt8 },
  { name: 'n', type: vstruct.UInt8 }, // log2(n)
  { name: 'r', type: vstruct.UInt8 },
  { name: 'p', type: vstruct.UInt8 },
  { name: 'salt', type: vstruct.Buffer(SALT_LEN_BYTES) },
  { name: 'iv', type: vstruct.Buffer(IV_LEN_BYTES) },
  { name: 'authTag', type: vstruct.Buffer(16) },
  { name: 'secret', type: vstruct.VarBuffer(vstruct.UInt32BE) }
])

function createScryptOptions (scryptOpts) {
  return Object.assign({}, { salt: crypto.randomBytes(SALT_LEN_BYTES), n: 16384, r: 8, p: 1 }, scryptOpts)
}

// NOTE: currently, always returns 256 bit keys
function stretchPassphrase (passphrase, scryptOpts) {
  assert(Buffer.isBuffer(passphrase) || typeof passphrase === 'string', 'paspshrase must a string or Buffer')
  const so = createScryptOptions(scryptOpts)
  assert.strictEqual(so.salt.length, SALT_LEN_BYTES, `salt must be ${SALT_LEN_BYTES} bytes`)

  const key = scrypt(passphrase, so.salt, so.n, so.r, so.p, 32)
  return Object.assign({}, so, { key: key })
}

function aesEncrypt (key, message, iv) {
  assert(Buffer.isBuffer(key), 'key must be a buffer')
  assert(Buffer.isBuffer(message), 'message must be a buffer')
  iv = iv || crypto.randomBytes(IV_LEN_BYTES)
  assert.strictEqual(iv.length, IV_LEN_BYTES, `iv must be ${IV_LEN_BYTES} bytes`)

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const secret = Buffer.concat([cipher.update(message), cipher.final()])
  const authTag = cipher.getAuthTag()

  return { authTag: authTag, iv: iv, secret: secret }
}

function aesDecrypt (key, secret, opts) {
  assert(Buffer.isBuffer(key), 'key must be a buffer')
  assert(Buffer.isBuffer(secret), 'message must be a buffer')
  assert(opts.iv, 'must pass iv')
  assert(opts.authTag, 'must pass authTag')

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, opts.iv)
  decipher.setAuthTag(opts.authTag)
  const message = Buffer.concat([decipher.update(secret), decipher.final()])

  return message
}

function encrypt (message, passphrase, opts) {
  assert(Buffer.isBuffer(passphrase) || typeof passphrase === 'string', 'passphrase must a string or Buffer')
  assert(Buffer.isBuffer(message), 'message must be a Buffer')
  opts = Object.assign({}, opts)

  let stretchedData = stretchPassphrase(passphrase, opts)
  let secretData = aesEncrypt(stretchedData.key, message, opts.iv)

  // don't want to return this so that the user doesn't accidentally store it
  delete stretchedData.key

  let data = Object.assign({}, stretchedData, secretData)

  // change n
  data.n = Math.log2(data.n)
  return struct.encode(data)
}

function decrypt (secret, passphrase) {
  assert(Buffer.isBuffer(passphrase) || typeof passphrase === 'string', 'paspshrase must a string or Buffer')
  assert(Buffer.isBuffer(secret), 'parameter "secret" must be a Buffer')
  let opts = struct.decode(secret)
  opts.n = Math.pow(2, opts.n)

  const secretMessage = opts.secret

  const stretchedData = stretchPassphrase(passphrase, opts)
  const message = aesDecrypt(stretchedData.key, secretMessage, opts)

  return message
}

module.exports = {
  decrypt: decrypt,
  encrypt: encrypt,
  struct: struct
}
