(function () {
  class BlockBook {}

  let Encryption = require('./encryptionUtils')

  BlockBook.prototype.startUp = function (username, email, password) {
    return Encryption.generateKeyPair(username, email, password).then(keyPair => {
      return keyPair
    })
  }

  module.exports = BlockBook
})()
