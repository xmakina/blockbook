(function () {
  const openpgp = require('openpgp')

  module.exports = function (plaintext, publicKey) {
    if (Array.isArray(publicKey) === false) {
      throw new Error('publicKey is not an array')
    }

    var options = {
      data: plaintext,
      publicKeys: openpgp.key.readArmored(publicKey.join('\n')).keys
    }

    return openpgp.encrypt(options).then(function (ciphertext) {
      return ciphertext.data.split(/\r?\n|\r/g)
    })
  }
})()
