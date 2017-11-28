/* eslint-env mocha */
(function () {
  let assert = require('chai').assert
  const Encryption = require('../src/encryptionUtils')
  const KeyPair = require('../src/KeyPair.js')
  const alice = require('./alice.js')
  const bob = require('./bob.js')

  describe('encrypt a message', () => {
    const inputText = 'Hello World'

    let keyPair
    let decrypted
    let encrypted
    before(() => {
      return Encryption.generateKeyPair('bob', 'bob@example.com', 'bob-password', 1024).then(generatedKeyPair => {
        keyPair = generatedKeyPair
        return keyPair.encrypt(inputText)
      }).then(encryptedText => {
        encrypted = encryptedText
        return keyPair.decrypt(encrypted)
      }).then(decryptedText => {
        decrypted = decryptedText
      })
    })

    it('should have saved the password', () => {
      assert.equal(keyPair.password, 'bob-password')
    })

    it('should be unencryped', () => {
      assert.equal(keyPair.privateKey[0], '-----BEGIN PGP PRIVATE KEY BLOCK-----')
    })

    it('should have encrypted', () => {
      assert.equal(encrypted.length, 12)
    })
    it('can be decrypted', () => {
      assert.equal(decrypted, inputText)
    })
  })

  describe('decrypt a message', () => {
    const cipherText = ['-----BEGIN PGP MESSAGE-----', 'Version: OpenPGP.js v2.5.12', 'Comment: https://openpgpjs.org', '', 'wYwDcuyuSo6ZCDMBA/9ZPXJ124jS0S8jt8wQwRC93FwifgxcDlPhidQYrgje', 'CCKNcm37WMxpx3Z22SKNHhvyd3bERlRaSCMQX+jphxfUCn8L8mlpjahm3LN/', 'x4miS6I8Vb4koL5TMt8yl0wAsg6j2s7o6d/+B1gUgH4wuh5y2taFEM+pN9CT', 'KdY+T7AKodJDAWfY3sAttItQCsvCnAIpTkO00cNYwABZFIlLi23qFCJcfE6i', 'm6+GHsWzbz91U/R+v9d+jPkYVjXfjtitiWRphwhOJw==', '=xp3w', '-----END PGP MESSAGE-----', '']
    let result

    before(() => {
      let keyPair = new KeyPair(alice.publicKey, alice.privateKey, alice.password)
      return keyPair.decrypt(cipherText).then(plainText => {
        result = plainText
      })
    })

    it('should have decrypted', () => {
      assert.equal(result, 'Hello World')
    })
  })

  describe('encrypt and decrypt a keypair', () => {
    let password = 'group-name'
    let keyPair = new KeyPair(alice.publicKey, alice.privateKey, alice.password)
    let encryptedKeyPair
    let decryptedKeyPair

    before(() => {
      let userDetails = alice.userDetails
      return Encryption.generateEncryptedKeyPair({keyPair, userDetails, password, numBits: 1024}).then(generatedEncryptedKeyPair => {
        encryptedKeyPair = generatedEncryptedKeyPair
        return generatedEncryptedKeyPair
      }).then((generatedEncryptedKeyPair) => {
        return Encryption.decryptEncryptedKeyPair({encryptedKeyPair, keyPair, password}).then(generatedDecryptedKeyPair => {
          decryptedKeyPair = generatedDecryptedKeyPair
        })
      })
    })

    it('should have encrypted the private key', () => {
      assert.equal(encryptedKeyPair.privateKey[0], '-----BEGIN PGP MESSAGE-----')
    })

    it('should have decrypted the private key', () => {
      assert.equal(decryptedKeyPair.privateKey[0], '-----BEGIN PGP PRIVATE KEY BLOCK-----')
    })
  })

  describe('re-encrypt a keypair', () => {
    let password = 'group-name'
    let originalKeyPair
    let ownerKeyPair = new KeyPair(alice.publicKey, alice.privateKey, alice.password)
    let targetKeyPair = new KeyPair(bob.publicKey)
    let newKeyPair

    before(() => {
      let userDetails = alice.userDetails
      return Encryption.generateEncryptedKeyPair({keyPair: ownerKeyPair, userDetails, password, numBits: 1024}).then(generatedEncryptedKeyPair => {
        originalKeyPair = generatedEncryptedKeyPair
      }).then(() => {
        return Encryption.reencryptKeyPair({originalKeyPair, ownerKeyPair, targetKeyPair}).then(result => {
          newKeyPair = result
        })
      })
    })

    it('should encrypt the private key', () => {
      assert.equal(newKeyPair.privateKey[0], '-----BEGIN PGP MESSAGE-----')
    })

    it('should be possible for the target key to decrypt', () => {
      return Encryption.decryptEncryptedKeyPair({encryptedKeyPair: newKeyPair, keyPair: new KeyPair(bob.publicKey, bob.privateKey, bob.password), password: 'group-name'}).then(result => {
        assert.equal(result.privateKey[0], '-----BEGIN PGP PRIVATE KEY BLOCK-----')
      })
    })
  })

  describe('encrypt a message for multiple keypairs', function () {
    this.timeout(15000)
    let groupOne = 'group-one'
    let groupTwo = 'group-two'

    let groupOneKeyPair
    let groupTwoKeyPair

    let aliceKeyPair = new KeyPair(alice.publicKey, alice.privateKey, alice.password)
    let bobKeyPair = new KeyPair(bob.publicKey, bob.privateKey, bob.password)
    let userDetails = alice.userDetails

    let content = 'Hello World!'

    let results

    before(() => {
      let groupOneGeneration = Encryption.generateEncryptedKeyPair({keyPair: aliceKeyPair, userDetails, password: groupOne, numBits: 1024}).then(generatedKeyPair => {
        groupOneKeyPair = generatedKeyPair
      })
      let groupTwoGeneration = Encryption.generateEncryptedKeyPair({keyPair: bobKeyPair, userDetails, password: groupTwo, numBits: 1024}).then(generatedKeyPair => {
        groupTwoKeyPair = generatedKeyPair
      })

      return Promise.all([groupOneGeneration, groupTwoGeneration]).then(() => {
        return Encryption.encryptForKeyPairs({keyPairs: [groupOneKeyPair, groupTwoKeyPair], content})
      }).then(generatedResults => {
        results = generatedResults
      })
    })

    it('should have encrypted for group one', () => {
      assert.equal(results[groupOneKeyPair.publicKey][0], '-----BEGIN PGP MESSAGE-----')
    })

    it('should have encrypted for group two', () => {
      assert.equal(results[groupTwoKeyPair.publicKey][0], '-----BEGIN PGP MESSAGE-----')
    })

    it('alice can decrypt group one', () => {
      return Encryption.decryptEncryptedKeyPair({encryptedKeyPair: groupOneKeyPair, keyPair: aliceKeyPair}).then(decryptedKeyPair => {
        return decryptedKeyPair.decrypt(results[groupOneKeyPair.publicKey])
      }).then(decrypted => {
        assert.equal(decrypted, content)
      })
    })

    it('bob can decrypt group two', () => {
      return Encryption.decryptEncryptedKeyPair({encryptedKeyPair: groupTwoKeyPair, keyPair: bobKeyPair}).then(decryptedKeyPair => {
        return decryptedKeyPair.decrypt(results[groupTwoKeyPair.publicKey])
      }).then(decrypted => {
        assert.equal(decrypted, content)
      })
    })

    it('alice can not decrypt group two', () => {
      return Encryption.decryptEncryptedKeyPair({encryptedKeyPair: groupTwoKeyPair, keyPair: aliceKeyPair}).then(decryptedKeyPair => {
        assert.equal(decryptedKeyPair, null)
      })
    })

    it('group one can not decrypt group two', () => {
      return Encryption.decryptEncryptedKeyPair({encryptedKeyPair: groupTwoKeyPair, keyPair: bobKeyPair}).then(decryptedKeyPair => {
        return decryptedKeyPair.decrypt(results[groupOneKeyPair.publicKey])
      }).then(decrypted => {
        assert.equal(decrypted, null)
      })
    })
  })
})()
