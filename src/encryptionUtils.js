(function () {
  const openpgp = require('openpgp')

  let KeyPair = require('./KeyPair.js')

  module.exports = {
    generateKeyPair: generateKeyPair,
    generateEncryptedKeyPair: generateEncryptedKeyPair,
    decryptEncryptedKeyPair: decryptEncryptedKeyPair,
    encryptForKeyPairs: encryptForKeyPairs,
    reencryptKeyPair: reencryptKeyPair
  }

  function generateKeyPair (name, email, password, numBits = 4096) {
    let options = {
      userIds: [{ name, email }],
      numBits: numBits,
      passphrase: password
    }

    return openpgp.generateKey(options).then(key => {
      return new KeyPair(key.publicKeyArmored.split(/\r?\n|\r/g), key.privateKeyArmored.split(/\r?\n|\r/g), password)
    })
  }

  // Create a keyPair with the private key encrypted behind the provided publicKey
  function generateEncryptedKeyPair (options) {
    if (options.keyPair === undefined) {
      throw new Error('keyPair not defined')
    }
    let keyPair = options.keyPair

    if (options.userDetails === undefined) {
      throw new Error('userDetails not defined')
    }
    let userDetails = options.userDetails

    if (options.password === undefined) {
      throw new Error('password not defined')
    }
    let password = options.password

    let numBits = 4096
    if (options.numBits !== undefined) {
      numBits = options.numBits
    }

    return generateKeyPair(userDetails.name, userDetails.email, password, numBits).then(newPair => {
      return keyPair.encrypt(newPair.privateKey.join('\n')).then((encPrivateKey) => {
        return new KeyPair(newPair.publicKey, encPrivateKey, password)
      })
    })
  }

  function reencryptKeyPair (options) {
    if (options.originalKeyPair === undefined) {
      throw new Error('originalKey not defined')
    }
    let originalKeyPair = options.originalKeyPair

    if (options.ownerKeyPair === undefined) {
      throw new Error('ownerkeyPair not defined')
    }

    if (options.targetKeyPair === undefined) {
      throw new Error('targetKey not defined')
    }

    return decryptEncryptedKeyPair({encryptedKeyPair: originalKeyPair, keyPair: options.ownerKeyPair}).then(decryptedKey => {
      return options.targetKeyPair.encrypt(decryptedKey.privateKey.join('\n'))
    }).then(encryptedPrivateKey => {
      return new KeyPair(originalKeyPair.publicKey, encryptedPrivateKey, originalKeyPair.password)
    })
  }

  function decryptEncryptedKeyPair (options) {
    if (options.encryptedKeyPair === undefined) {
      throw new Error('encryptedKeyPair required')
    }
    let encryptedKeyPair = options.encryptedKeyPair

    if (options.keyPair === undefined) {
      throw new Error('keyPair required')
    }
    let keyPair = options.keyPair

    return keyPair.decrypt(encryptedKeyPair.privateKey).then(decryptedPrivateKey => {
      if (decryptedPrivateKey === null) {
        return null
      }
      return new KeyPair(encryptedKeyPair.publicKey, decryptedPrivateKey.split(/\r?\n|\r/g), encryptedKeyPair.password)
    })
  }

  function encryptForKeyPairs (options) {
    if (options.keyPairs === undefined) {
      throw new Error('keyPairs required')
    }
    let keyPairs = options.keyPairs

    if (options.content === undefined) {
      throw new Error('content required')
    }
    let content = options.content

    let promiseChain = []
    for (let i = 0; i < keyPairs.length; i++) {
      let keyPair = keyPairs[i]

      promiseChain.push(keyPair.encrypt(content).then(encryptedPost => {
        return { encryptedPost, publicKey: keyPair.publicKey }
      }).catch(err => {
        throw err
      }))
    }

    let groupContent = {}
    return Promise.all(promiseChain).then((encryptedPosts) => {
      for (var i = 0; i < encryptedPosts.length; i++) {
        let encryptedPost = encryptedPosts[i]
        groupContent[encryptedPost.publicKey] = (encryptedPost.encryptedPost)
      }

      return groupContent
    })
  }
})()
