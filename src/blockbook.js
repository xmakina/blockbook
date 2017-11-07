(function () {
  const openpgp = require('openpgp')
  class BlockBook {
    constructor (numBits) {
      this.numBits = numBits || 1024
    }
  }

  module.exports = BlockBook

  BlockBook.prototype.generate = function (oldState, userDetails, password) {
    let newState = JSON.parse(JSON.stringify(oldState))
    if (userDetails === undefined) {
      throw new Error('userDetails not in state')
    }

    let options = {
      userIds: [{name: userDetails.name, email: userDetails.email}],
      numBits: this.numBits,
      passphrase: password
    }

    return openpgp.generateKey(options).then(key => {
      newState = {
        publicKey: key.publicKeyArmored.split(/\r?\n|\r/g),
        privateKey: key.privateKeyArmored.split(/\r?\n|\r/g)
      }

      return newState
    })
  }

  BlockBook.prototype.encrypt = require('./encrypt')

  BlockBook.prototype.decrypt = require('./decrypt')

  BlockBook.prototype.createGroup = function (oldState, groupName) {
    let newState = JSON.parse(JSON.stringify(oldState))
    if (oldState.publicKey === undefined) {
      throw new Error('Public Key is not set in state')
    }

    if (oldState.groups === undefined) {
      newState.groups = {}
    }

    return this.generate(oldState.userDetails, groupName).then(keyPair => {
      return this.encrypt(keyPair.privateKey.join('\n'), oldState.publicKey).then((encPrivateKey) => {
        newState.groups[groupName] = {
          publicKey: keyPair.publicKey,
          privateKey: encPrivateKey
        }

        return newState
      })
    })
  }

  BlockBook.prototype.addToGroup = function (state, groupName, targetName, targetPublicKey, privateKey, password) {
    if (state.publicKey === targetPublicKey) {
      throw new Error("That's your public key, bucko!")
    }

    return this.decrypt(state.groups[groupName].privateKey, privateKey, password)
      .then(groupPrivateKey => {
        return this.addGroupToConnection(state, targetName, targetPublicKey, groupName, groupPrivateKey).then(newState => {
          return newState
        })
      }).catch(err => {
        console.error(err)
      })
  }

  BlockBook.prototype.addGroupToConnection = function (oldState, targetName, targetPublicKey, groupName, groupPrivateKey) {
    let newState = JSON.parse(JSON.stringify(oldState))
    if (oldState.connections === undefined) {
      newState.connections = {}
    }

    if (!oldState.connections || oldState.connections[targetName] === undefined) {
      newState.connections[targetName] = {}
    }

    if (!oldState.connections || oldState.connections[targetName].groups === undefined) {
      newState.connections[targetName].groups = {}
    }

    return this.encrypt(groupPrivateKey, targetPublicKey).then(encryptedGroupKey => {
      newState.connections[targetName].groups[groupName] = encryptedGroupKey
      return newState
    })
  }

  BlockBook.prototype.post = function (oldState, content, groups, privateKey, password) {
    let newState = JSON.parse(JSON.stringify(oldState))
    if (oldState.groups === undefined) {
      throw new Error('Groups not in state')
    }

    let promiseChain = []
    for (let i = 0; i < groups.length; i++) {
      let group = groups[i]
      if (oldState.groups[group] === undefined) {
        throw new Error(`Group ${group} not defined`)
      }
      if (oldState.groups[group].posts === undefined) {
        newState.groups[group].posts = []
      }

      promiseChain.push(this.encrypt(content, oldState.groups[group].publicKey).then(encryptedForGroup => {
        return {encryptedForGroup, group}
      }).catch(err => {
        throw err
      }))
    }

    return Promise.all(promiseChain).then((encryptedPosts) => {
      for (var i = 0; i < encryptedPosts.length; i++) {
        let encryptedPost = encryptedPosts[i]
        newState.groups[encryptedPost.group].posts.push(encryptedPost.encryptedForGroup)
      }

      return newState
    })
  }

  BlockBook.prototype.readContent = function (userDetails, targetState, privateKey, password) {
    if (targetState.connections === undefined || targetState.connections[userDetails.name] === undefined) {
      throw new Error('You are not a connection')
    }

    let promiseChain = []
    let posts = []
    for (let group in targetState.connections[userDetails.name].groups) {
      let decryptGroup = this.decrypt(targetState.connections[userDetails.name].groups[group], privateKey, password)
      .then(groupPrivateKey => {
        let postPromiseChain = []
        for (let i = 0; i < targetState.groups[group].posts.length; i++) {
          let post = targetState.groups[group].posts[i]
          let decryptPost = this.decrypt(post, groupPrivateKey.split(/\r?\n|\r/g), group).then(post => {
            posts.push(post)
          }).catch(err => {
            throw new Error(err)
          })
          postPromiseChain.push(decryptPost)
        }

        return Promise.all(postPromiseChain)
      }).catch(err => {
        throw new Error(err)
      })

      promiseChain.push(decryptGroup)
    }

    return Promise.all(promiseChain).then(() => {
      return posts
    })
  }
})()
