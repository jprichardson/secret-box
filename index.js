const assert = require('assert')
const crypto = require('crypto')
const scrypt = require('scryptsy')

// http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf 8.2.2 RBG-based Construction (about initialization vectors)
// always 12, any other value will error, not sure why it won't allow higher... probably concat with freefield?
const IV_LEN_BYTES = 12

function createScryptOptions (scryptOpts) {
  return Object.assign({}, { salt: crypto.randomBytes(32), n: 16384, r: 8, p: 1 }, scryptOpts)
}

// NOTE: currently, always returns 256 bit keys
function stretchPassphrase (passphrase, scryptOpts) {
  assert(Buffer.isBuffer(passphrase) || typeof passphrase === 'string', 'paspshrase must a string or Buffer')
  const so = createScryptOptions(scryptOpts)

  const key = scrypt(passphrase, so.salt, so.n, so.r, so.p, 32)
  return Object.assign({}, so, { key: key })
}

function aesEncrypt (key, message, iv) {
  assert(Buffer.isBuffer(key), 'key must be a buffer')
  assert(Buffer.isBuffer(message), 'message must be a buffer')
  iv = iv || crypto.randomBytes(IV_LEN_BYTES)

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

function encrypt (passphrase, message, opts) {
  assert(Buffer.isBuffer(passphrase) || typeof passphrase === 'string', 'paspshrase must a string or Buffer')
  assert(Buffer.isBuffer(message), 'message must be a Buffer')
  opts = Object.assign({}, opts)

  let stretchedData = stretchPassphrase(passphrase, opts)
  let secretData = aesEncrypt(stretchedData.key, message, opts.iv)

  // don't want to return this so that the user doesn't accidentally store it
  delete stretchedData.key

  return Object.assign({}, stretchedData, secretData)
}

function decrypt (passphrase, secret, opts) {
  assert(Buffer.isBuffer(passphrase) || typeof passphrase === 'string', 'paspshrase must a string or Buffer')
  if (!Buffer.isBuffer(secret) && typeof secret === 'object') {
    opts = secret
    secret = opts.secret
  }

  const stretchedData = stretchPassphrase(passphrase, opts)
  const message = aesDecrypt(stretchedData.key, secret, opts)

  return message
}

module.exports = {
  decrypt: decrypt,
  encrypt: encrypt
}
