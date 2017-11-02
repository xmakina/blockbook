(function () {
  const openpgp = require('openpgp')
  class BlockBook {
    constructor (numBits) {
      this.numBits = numBits || 1024
    }
  }

  module.exports = BlockBook

  BlockBook.prototype.generate = function (state, password) {
    if (state.userDetails === undefined) {
      throw new Error('Userdetails not in state')
    }

    var options = {
      userIds: [state.userDetails],
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

  BlockBook.prototype.encrypt = require('./encrypt')

  BlockBook.prototype.decrypt = require('./decrypt')

  BlockBook.prototype.createGroup = function (state, groupName, password) {
    if (state.groups === undefined) {
      state.groups = {}
    }

    if (state.publicKey === undefined) {
      throw new Error('Public Key is not set in state')
    }

    return this.generate(state, password).then(keyPair => {
      return this.encrypt(keyPair.privateKey.join('\n'), state.publicKey).then((encPrivateKey) => {
        state.groups[groupName] = {
          publicKey: keyPair.publicKey,
          privateKey: encPrivateKey
        }

        return state
      })
    })
  }

  BlockBook.prototype.addToGroup = function (state, groupName, targetName, targetPublicKey, privateKey, password) {
    return this.decrypt(state.groups[groupName].privateKey, privateKey, password)
      .then(groupPrivateKey => {
        return this.addGroupToConnection(state, targetName, targetPublicKey, groupName, groupPrivateKey)
      }).catch(err => {
        console.error(err)
      })
  }

  BlockBook.prototype.addGroupToConnection = function (state, targetName, targetPublicKey, groupName, groupPrivateKey) {
    if (state.connections === undefined) {
      state.connections = {}
    }

    if (state.connections[targetName] === undefined) {
      state.connections[targetName] = {}
    }

    if (state.connections[targetName].groups === undefined) {
      state.connections[targetName].groups = {}
    }

    return this.encrypt(groupPrivateKey, targetPublicKey).then(encryptedGroupKey => {
      state.connections[targetName].groups[groupName] = encryptedGroupKey
      return state
    })
  }

  BlockBook.prototype.post = function (state, content, groups, privateKey, password) {
    if (state.groups === undefined) {
      throw new Error('Groups not in state')
    }

    let promiseChain = []
    for (var i = 0; i < groups.length; i++) {
      let group = groups[i]

      if (state.groups[group].posts === undefined) {
        state.groups[group].posts = []
      }

      promiseChain.push(this.encrypt(content, state.groups[group].publicKey).then(encryptedForGroup => {
        state.groups[group].posts.push(encryptedForGroup)
      }))
    }

    return Promise.all(promiseChain).then(() => { return state })
  }

  BlockBook.prototype.readContent = function (state, targetState, privateKey, password) {
    var promiseChain = []
    for (var group in targetState.connections[state.userDetails.name].groups) {
      let decryptGroup = this.decrypt(targetState.groups[group].privateKey, privateKey, password).then(groupPrivateKey => {

      })

      promiseChain.push(decryptGroup)
    }
  }
})()
