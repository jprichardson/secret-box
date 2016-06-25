var crypto = require('crypto')
var test = require('tape')
var secretBox = require('../')

test('encrypt / decrypt', function (t) {
  t.plan(1)

  const passphrase = 'open sesame'
  const message = new Buffer('The secret launch code is 1234.')

  const message2 = secretBox.decrypt(passphrase, secretBox.encrypt(passphrase, message))
  t.is(message.toString('hex'), message2.toString('hex'), 'encrypt / decrypt message')

  t.end()
})

test('encrypt / decrypt (buffer phassphrase)', function (t) {
  t.plan(1)

  const passphrase = new Buffer('open sesame 2')
  const message = new Buffer('The secret launch code is 1234.')

  const message2 = secretBox.decrypt(passphrase, secretBox.encrypt(passphrase, message))
  t.is(message.toString('hex'), message2.toString('hex'), 'encrypt / decrypt message')

  t.end()
})

test('encrypt / decrypt (tune up N in scrypt)', function (t) {
  t.plan(2)
  console.time('scrypt-n')

  const passphrase = new Buffer('open sesame 2')
  const message = new Buffer('The secret launch code is 1234.')

  const data = secretBox.encrypt(passphrase, message, { n: Math.pow(2, 16) })
  t.is(data.n, Math.pow(2, 16), 'n is set properly')

  const message2 = secretBox.decrypt(passphrase, data)
  t.is(message.toString('hex'), message2.toString('hex'), 'encrypt / decrypt message')

  console.timeEnd('scrypt-n')
  t.end()
})

test('encrypt / decrypt (set salt)', function (t) {
  t.plan(2)

  const passphrase = new Buffer('open sesame 2')
  const message = new Buffer('The secret launch code is 1234.')
  const salt = crypto.randomBytes(32)

  const data = secretBox.encrypt(passphrase, message, { n: 512, salt: salt })
  t.deepEqual(data.salt, salt, 'salt set')

  const message2 = secretBox.decrypt(passphrase, data)
  t.is(message.toString('hex'), message2.toString('hex'), 'encrypt / decrypt message')

  delete data.secret

  t.end()
})
