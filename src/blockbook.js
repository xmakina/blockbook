(function () {
  const openpgp = require('openpgp')
  class BlockBook {
    constructor (userDetails, publicKey, state, numBits) {
      this.userDetails = userDetails
      if (numBits === null) {
        this.numBits = 4096
      } else {
        this.numBits = numBits
      }
      if (state.publicKey === undefined) {
        this.state = {
          publicKey: publicKey
        }
      } else {
        this.state = state
      }
    }
  }

  module.exports = BlockBook

  BlockBook.prototype.generate = function (password) {
    var options = {
      userIds: [this.userDetails],
      numBits: this.numBits,
      passphrase: password
    }

    return openpgp.generateKey(options).then(key => {
      return {
        publicKey: key.publicKeyArmored.split(/\r?\n|\r/g),
        privateKey: key.privateKeyArmored.split(/\r?\n|\r/g)
      }
    })
  }

  BlockBook.prototype.encrypt = function (plaintext, publicKey) {
    var options = {
      data: plaintext,
      publicKeys: openpgp.key.readArmored(publicKey.join('\n')).keys
    }

    return openpgp.encrypt(options).then(function (ciphertext) {
      return ciphertext.data.split(/\r?\n|\r/g)
    })
  }

  BlockBook.prototype.decrypt = function (ciphertext, privateKey, password) {
    if (Array.isArray(ciphertext) === false) {
      throw new Error('ciphertext is not an array')
    }

    if (Array.isArray(privateKey) === false) {
      throw new Error('privateKey is not an array')
    }

    var privKeyObj = openpgp.key.readArmored(privateKey.join('\n')).keys[0]
    privKeyObj.decrypt(password)

    let options = {
      message: openpgp.message.readArmored(ciphertext.join('\n')),
      privateKey: privKeyObj
    }

    return openpgp.decrypt(options).then(function (plaintext) {
      return plaintext.data
    })
  }

  BlockBook.prototype.getState = function () {
    return this.state
  }

  BlockBook.prototype.createGroup = function (groupName, password) {
    if (this.state.groups === undefined) {
      this.state.groups = {}
    }

    return this.generate(password).then(keyPair => {
      return this.encrypt(keyPair.privateKey.join('\n'), this.state.publicKey).then((encPrivateKey) => {
        this.state.groups[groupName] = {
          publicKey: keyPair.publicKey,
          privateKey: encPrivateKey
        }
      })
    })
  }

  BlockBook.prototype.addToGroup = function (groupName, targetName, targetPublicKey, privateKey, password) {
    return this.decrypt(this.state.groups[groupName].privateKey, privateKey, password)
      .then(groupPrivateKey => {
        return this.addGroupToConnection(targetName, targetPublicKey, groupName, groupPrivateKey)
      }).catch(err => {
        console.error(err)
      })
  }

  BlockBook.prototype.addGroupToConnection = function (targetName, targetPublicKey, groupName, groupPrivateKey) {
    if (this.state.connections === undefined) {
      this.state.connections = {}
    }

    if (this.state.connections[targetName] === undefined) {
      this.state.connections[targetName] = {}
    }

    if (this.state.connections[targetName].groups === undefined) {
      this.state.connections[targetName].groups = []
    }

    return this.encrypt(groupPrivateKey, targetPublicKey).then(encryptedGroupKey => {
      this.state.connections[targetName].groups.push({name: groupName, key: groupPrivateKey})
    })
  }
})()
