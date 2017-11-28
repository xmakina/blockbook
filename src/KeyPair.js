(function () {
  let Encrypt = require('./encrypt')
  let Decrypt = require('./decrypt')

  class KeyPair {
    constructor (publicKey, privateKey, password) {
      if (Array.isArray(publicKey) === false) {
        throw new Error('publicKey must be an array')
      }

      this.publicKey = publicKey
      this.privateKey = privateKey
      this.password = password
    }
  }

  KeyPair.prototype.encrypt = function (plainText) {
    return Encrypt(plainText, this.publicKey)
  }

  KeyPair.prototype.decrypt = function (cipherText) {
    if (Array.isArray(this.privateKey) === false) {
      throw new Error('privateKey must be an array')
    }

    if (this.password === undefined) {
      throw new Error('password is required')
    }

    return Decrypt(cipherText, this.privateKey, this.password)
  }

  module.exports = KeyPair
})()
