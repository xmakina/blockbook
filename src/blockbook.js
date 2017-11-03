(function () {
  const openpgp = require('openpgp')
  class BlockBook {
    constructor (numBits) {
      this.numBits = numBits || 1024
    }
  }

  module.exports = BlockBook

  BlockBook.prototype.generate = function (userDetails, password) {
    if (userDetails === undefined) {
      throw new Error('userDetails not in state')
    }

    let options = {
      userIds: [{name: userDetails.name, email: userDetails.email}],
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

  BlockBook.prototype.createGroup = function (state, groupName) {
    if (state.groups === undefined) {
      state.groups = {}
    }

    if (state.publicKey === undefined) {
      throw new Error('Public Key is not set in state')
    }

    return this.generate(state.userDetails, groupName).then(keyPair => {
      return this.encrypt(keyPair.privateKey.join('\n'), state.publicKey).then((encPrivateKey) => {
        state.groups[groupName] = {
          publicKey: keyPair.publicKey,
          privateKey: encPrivateKey
        }
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
      console.log(`encrypted ${groupName} key for ${targetName}`)
      state.connections[targetName].groups[groupName] = encryptedGroupKey
      return state
    })
  }

  BlockBook.prototype.post = function (state, content, groups, privateKey, password) {
    if (state.groups === undefined) {
      throw new Error('Groups not in state')
    }

    let promiseChain = []
    for (let i = 0; i < groups.length; i++) {
      let group = groups[i]
      if (state.groups[group] === undefined) {
        throw new Error(`Group ${group} not defined`)
      }
      if (state.groups[group].posts === undefined) {
        state.groups[group].posts = []
      }

      promiseChain.push(this.encrypt(content, state.groups[group].publicKey).then(encryptedForGroup => {
        state.groups[group].posts.push(encryptedForGroup)
      }).catch(err => {
        throw err
      }))
    }

    return Promise.all(promiseChain).then(() => { return state })
  }

  BlockBook.prototype.readContent = function (userDetails, targetState, privateKey, password) {
    if (targetState.connections[userDetails.name] === undefined) {
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
            console.log(post.join('\n'))
            console.log(groupPrivateKey)
            console.log(group)
            throw new Error(err)
          })
          postPromiseChain.push(decryptPost)
        }

        return Promise.all(postPromiseChain)
      }).catch(err => {
        console.log(targetState.connections[userDetails.name].groups[group].join('\n'))
        console.log(privateKey.join('\n'))
        console.log(password)
        throw new Error(err)
      })

      promiseChain.push(decryptGroup)
    }

    return Promise.all(promiseChain).then(() => {
      return posts
    })
  }
})()
