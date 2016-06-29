var crypto = require('crypto')
var test = require('tape')
var secretBox = require('../')

test('encrypt / decrypt', function (t) {
  t.plan(1)

  const passphrase = 'open sesame'
  const message = new Buffer('The secret launch code is 1234.')

  const message2 = secretBox.decrypt(secretBox.encrypt(message, passphrase), passphrase)
  t.is(message.toString('hex'), message2.toString('hex'), 'encrypt / decrypt message')

  t.end()
})

test('encrypt / decrypt (buffer phassphrase)', function (t) {
  t.plan(1)

  const passphrase = new Buffer('open sesame 2')
  const message = new Buffer('The secret launch code is 1234.')

  const message2 = secretBox.decrypt(secretBox.encrypt(message, passphrase), passphrase)
  t.is(message.toString('hex'), message2.toString('hex'), 'encrypt / decrypt message')

  t.end()
})

test('encrypt / decrypt (tune up N in scrypt)', function (t) {
  t.plan(2)
  console.time('scrypt-n')

  const passphrase = new Buffer('open sesame 2')
  const message = new Buffer('The secret launch code is 1234.')

  const n = Math.pow(2, 16)
  const data = secretBox.encrypt(message, passphrase, { n: n })
  const dataParams = secretBox.struct.decode(data)
  t.is(dataParams.n, Math.log2(n)) // <--- encoded as just power of 2.

  const message2 = secretBox.decrypt(data, passphrase)
  t.is(message.toString('hex'), message2.toString('hex'), 'encrypt / decrypt message')

  console.timeEnd('scrypt-n')
  t.end()
})

test('encrypt / decrypt (set salt)', function (t) {
  t.plan(2)

  const passphrase = new Buffer('open sesame 2')
  const message = new Buffer('The secret launch code is 1234.')
  const salt = crypto.randomBytes(16)

  const data = secretBox.encrypt(message, passphrase, { n: 512, salt: salt })
  const dataParams = secretBox.struct.decode(data)
  t.deepEqual(dataParams.salt, salt)

  const message2 = secretBox.decrypt(data, passphrase)
  t.is(message.toString('hex'), message2.toString('hex'), 'encrypt / decrypt message')

  delete data.secret

  t.end()
})
