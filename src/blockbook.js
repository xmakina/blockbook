(function () {
  class BlockBook {}

  let Encryption = require('./encryptionUtils')
  let KeyPair = require('./KeyPair')

  BlockBook.prototype.register = function (name, email, password) {
    return Encryption.generateKeyPair(name, email, password).then(keyPair => {
      return keyPair
    })
  }

  BlockBook.prototype.login = function (options) {
    if (options.name === undefined || options.name === '') {
      throw new Error('name must be specified')
    }

    if (options.email === undefined || options.email === '') {
      throw new Error('email must be specified')
    }

    if (options.keyPair === undefined) {
      throw new Error('keyPair must be specified')
    }

    if (options.numBits !== undefined) {
      this.numBits = options.numBits
    }

    return options.keyPair.encrypt('test').then(cipher => options.keyPair.decrypt(cipher)).then(plaintext => {
      if (plaintext === 'test') {
        this.keyPair = options.keyPair
        this.userDetails = {name: options.name, email: options.email}
      } else {
        throw new Error('Login failed')
      }
    })
  }

  BlockBook.prototype.addPost = function (options) {
    if (options.content === undefined || options.content === '') {
      throw new Error('content must be specified')
    }

    if (Array.isArray(options.key) === false) {
      throw new Error('key must be an array')
    }

    let targetKey = new KeyPair(options.key)

    return targetKey.encrypt(options.content).then(cipher => {
      return {publicKey: options.key, content: cipher}
    })
  }

  BlockBook.prototype.readPost = function (options) {
    if (options.publicKey !== this.keyPair.publicKey) {
      console.log('options.publicKey', options.publicKey)
      throw new Error('post public key does not match yours')
    }
    if (Array.isArray(options.content) === false) {
      throw new Error('post must be an array')
    }

    return this.keyPair.decrypt(options.content)
  }

  BlockBook.prototype.makeGroup = function (options) {
    if (options.name === undefined || options.name === '') {
      throw new Error('name must be specified')
    }

    return Encryption.generateEncryptedKeyPair({keyPair: this.keyPair, userDetails: this.userDetails, password: options.name, numBits: this.numBits}).then(pair => {
      pair.name = options.name
      return pair
    })
  }

  BlockBook.prototype.addToGroup = function (options) {
    if (options.group === undefined) {
      throw new Error('group must be an array')
    }

    if (Array.isArray(options.newMemberPublicKey) === false) {
      throw new Error('key must be an array')
    }
    let newMemberPublicKey = options.newMemberPublicKey

    return Encryption.reencryptKeyPair({ownerKeyPair: this.keyPair, originalKeyPair: options.group, targetKeyPair: new KeyPair(newMemberPublicKey)}).then(newKeyPair => {
      return {publicKey: newMemberPublicKey, privateKey: newKeyPair.privateKey}
    })
  }

  BlockBook.prototype.postToGroup = function (options) {
    if (options.content === undefined || options.content === '') {
      throw new Error('content must be specified')
    }

    if (options.group === undefined) {
      throw new Error('group must be specified')
    }

    return options.group.encrypt(options.content).then(cipher => {
      return cipher
    })
  }

  BlockBook.prototype.readPostFromGroup = function (options) {
    if (options.group === undefined) {
      throw new Error('group must be specified')
    }
    let group = options.group

    if (options.groupMember === undefined) {
      throw new Error('groupMember must be specified')
    }
    if (options.groupMember.publicKey !== this.keyPair.publicKey) {
      throw new Error('groupMember is not yours')
    }
    let groupMember = options.groupMember

    if (options.groupPost === undefined) {
      throw new Error('groupPost must be specified')
    }
    let groupPost = options.groupPost

    return Encryption.decryptEncryptedKeyPair({encryptedKeyPair: groupMember, keyPair: this.keyPair}).then(decryptedGroup => {
      let groupKeyPair = new KeyPair(group.publicKey, decryptedGroup.privateKey, group.name)
      return groupKeyPair.decrypt(groupPost)
    })
  }

  module.exports = BlockBook
})()
