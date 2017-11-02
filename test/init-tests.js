/* eslint-env mocha */
(function () {
  var assert = require('chai').assert
  const BlockBook = require('../index.js')

  let subject = null
  let result = null

  const alice = require('./alice')
  const bob = require('./bob')
  const states = require('./states')

  describe('during initialisation', () => {
    describe('with a new user', () => {
      const state = {}

      beforeEach(() => {
        subject = new BlockBook(alice.userDetails, alice.publicKey, state)
        result = subject.getState()
      })

      it('should set the public key', () => {
        assert.equal(result.publicKey, alice.publicKey)
      })
    })
  })

  describe('when a group is created', () => {
    const state = {
      publicKey: alice.publicKey
    }

    before(() => {
      subject = new BlockBook(alice.userDetails, alice.publicKey, state, 1024)
      return subject.createGroup('pals', alice.password).then(() => {
        result = subject.getState()
      })
    })

    it('should add a pals group', () => {
      assert.isOk(result.groups['pals'])
    })

    it('should add a private key', () => {
      assert.isOk(result.groups['pals'].privateKey)
    })

    it('should add a public key', () => {
      assert.isOk(result.groups['pals'].publicKey)
    })
  })

  // describe('when a key is generated', () => {
  //   it('should make a pair', () => {
  //     subject = new BlockBook(alice.userDetails, alice.publicKey, states.withpals, 1024)
  //     subject.generate(alice.password).then(keypair => {
  //       console.log(keypair)
  //     })
  //   })
  // })

  describe('when something is encrypted', () => {
    const inputText = 'Hello World'

    let decrypted
    let encrypted
    beforeEach(() => {
      subject = new BlockBook(alice.userDetails, alice.publicKey, states.withpals, 1024)
      return subject.encrypt(inputText, alice.publicKey).then((cipherText) => {
        encrypted = cipherText
        return subject.decrypt(cipherText, alice.privateKey, alice.password).then(plaintext => {
          decrypted = plaintext
        })
      })
    })

    it('should have encrypted', () => {
      assert.equal(encrypted.length, 12)
    })
    it('can be decrypted', () => {
      assert.equal(decrypted, inputText)
    })
  })

  describe('when something is decrypted', () => {
    const cipherText = ['-----BEGIN PGP MESSAGE-----', 'Version: OpenPGP.js v2.5.12', 'Comment: https://openpgpjs.org', '', 'wYwDcuyuSo6ZCDMBA/9ZPXJ124jS0S8jt8wQwRC93FwifgxcDlPhidQYrgje', 'CCKNcm37WMxpx3Z22SKNHhvyd3bERlRaSCMQX+jphxfUCn8L8mlpjahm3LN/', 'x4miS6I8Vb4koL5TMt8yl0wAsg6j2s7o6d/+B1gUgH4wuh5y2taFEM+pN9CT', 'KdY+T7AKodJDAWfY3sAttItQCsvCnAIpTkO00cNYwABZFIlLi23qFCJcfE6i', 'm6+GHsWzbz91U/R+v9d+jPkYVjXfjtitiWRphwhOJw==', '=xp3w', '-----END PGP MESSAGE-----', '']

    beforeEach(() => {
      subject = new BlockBook(alice.userDetails, alice.publicKey, states.withpals, 1024)
      return subject.decrypt(cipherText, alice.privateKey, alice.password).then((plainText) => {
        result = plainText
      })
    })

    it('should have decrypted', () => {
      assert.equal(result, 'Hello World')
    })
  })

  describe('when bob is added to pals', () => {
    const state = states.withpals

    beforeEach(() => {
      subject = new BlockBook(alice.userDetails, alice.publicKey, state)
      return subject.addToGroup('pals', 'bob.id', bob.publicKey, alice.privateKey, alice.password).then(() => {
        result = subject.getState()
      })
    })

    it('should add bob', () => {
      result.connections['bob.id'].groups = 'endcrypted text'
    })
  })
})()
