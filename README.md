secret-box
==========

[![npm][npm-image]][npm-url]
[![travis][travis-image]][travis-url]
[![standard][standard-image]][standard-url]

[npm-image]: https://img.shields.io/npm/v/secret-box.svg?style=flat-square
[npm-url]: https://www.npmjs.com/package/secret-box
[travis-image]: https://img.shields.io/travis/jprichardson/secret-box.svg?style=flat-square
[travis-url]: https://travis-ci.org/jprichardson/secret-box
[standard-image]: https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat-square
[standard-url]: http://npm.im/standard

Encrypt and decrypt secrets. Built on AES-256-GCM and Scrypt for now, may change later.

> Sponsored by [Exodus](http://www.exodus.io/) Bitcoin and Ethereum wallet.


## Install

```
npm install --save secret-box
```

## Usage

```js
var secretBox = require('secret-box')

const passphrase = new Buffer('open sesame 2')
const message = new Buffer('The secret launch code is 1234.')

const secret = secretBox.encrypt(message, passphrase)
const message2 = secretBox.decrypt(secret, passphrase)

console.log(message2.toString('utf8'))
// => The secret launch code is 1234.

```

## License

[MIT](LICENSE.md)
