/* eslint-env mocha */
(function () {
  var assert = require('chai').assert
  const BlockBook = require('../index.js')

  let subject = null
  let result = null

  const alice = require('./alice')
  const bob = require('./bob')
  let states = require('./states')

  describe('when a group is created', () => {
    let state = {
      userDetails: alice.userDetails,
      publicKey: alice.publicKey
    }

    before(() => {
      subject = new BlockBook(1024)
      return subject.createGroup(state, 'pals', alice.password).then(newState => {
        result = newState
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

  describe('when something is encrypted', () => {
    const inputText = 'Hello World'

    let decrypted
    let encrypted
    beforeEach(() => {
      subject = new BlockBook()
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
      subject = new BlockBook()
      return subject.decrypt(cipherText, alice.privateKey, alice.password).then((plainText) => {
        result = plainText
      })
    })

    it('should have decrypted', () => {
      assert.equal(result, 'Hello World')
    })
  })

  describe('when bob is added to pals', () => {
    let state = states.withPals

    beforeEach(() => {
      subject = new BlockBook()
      return subject.addToGroup(state, 'pals', 'bob.id', bob.publicKey, alice.privateKey, alice.password).then(newState => {
        result = newState
      })
    })

    it('should add bob', () => {
      assert.equal(result.connections['bob.id'].groups['pals'][0], '-----BEGIN PGP MESSAGE-----')
    })
  })

  describe('when alice makes a post for pals', () => {
    let state = states.withBobInPals

    beforeEach(() => {
      subject = new BlockBook()
      return subject.post(state, 'some content', ['pals'], alice.privateKey, alice.password).then(newState => {
        result = newState
      })
    })

    it('should add the post', () => {
      assert.isDefined(result.groups['pals'].posts[0])
      assert.equal(result.groups['pals'].posts[0][0], '-----BEGIN PGP MESSAGE-----')
    })
  })

  describe('when alice makes a post for pals and family', () => {
    let state = states.withBobInPals

    beforeEach(() => {
      subject = new BlockBook()
      return subject.createGroup(state, 'family', alice.password).then(newState => {
        return subject.post(newState, 'some content', ['pals', 'family'], alice.privateKey, alice.password).then(newState => {
          result = newState
        })
      })
    })

    it('should add the post to pals', () => {
      assert.isDefined(result.groups['pals'].posts[0])
      assert.equal(result.groups['pals'].posts[0][0], '-----BEGIN PGP MESSAGE-----')
    })

    it('should add the post to family', () => {
      assert.isDefined(result.groups['family'].posts[0])
      assert.equal(result.groups['family'].posts[0][0], '-----BEGIN PGP MESSAGE-----')
    })
  })

  describe('when bob reads a post from pals', () => {
    let bobState = {
      userDetails: bob.userDetails,
      publicKey: bob.publicKey
    }

    let aliceState = states.withAPostInPals

    beforeEach(() => {
      subject = new BlockBook()
      return subject.getContent(bobState, aliceState, bob.privateKey, bob.password).then(content => {
        result = content
      })
    })

    it('should add the post', () => {
      assert.equal(result.posts[0], 'some content')
    })
  })
})()
