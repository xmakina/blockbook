(function () {
  const openpgp = require('openpgp')

  module.exports = function (ciphertext, privateKey, password) {
    if (Array.isArray(ciphertext) === false) {
      throw new Error('ciphertext is not an array')
    }

    if (Array.isArray(privateKey) === false) {
      throw new Error('privateKey is not an array')
    }

    var privKeyObj = openpgp.key.readArmored(privateKey.join('\n')).keys[0]
    var keyDecrypted = privKeyObj.decrypt(password)
    if (!keyDecrypted) {
      throw new Error('Password is wrong')
    }

    let options = {
      message: openpgp.message.readArmored(ciphertext.join('\n')),
      privateKey: privKeyObj
    }

    return openpgp.decrypt(options).then(function (plaintext) {
      return plaintext.data
    }).catch(err => {
      throw err
    })
  }
})()
