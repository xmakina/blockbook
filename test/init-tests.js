/* eslint-env mocha */
(function () {
  let assert = require('chai').assert
  let openpgp = require('openpgp')
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
        state = newState
      })
    })

    it('should add a pals group', () => {
      assert.isOk(state.groups['pals'])
    })

    it('should add a private key', () => {
      assert.isOk(state.groups['pals'].privateKey)
    })

    it('should add a public key', () => {
      assert.isOk(state.groups['pals'].publicKey)
    })

    it('should be decryptable', () => {
      return subject.decrypt(state.groups['pals'].privateKey, alice.privateKey, alice.password).then(decryptedButLockedKey => {
        let privKeyObj = openpgp.key.readArmored(decryptedButLockedKey).keys[0]
        let keyDecrypted = privKeyObj.decrypt('pals')
        assert.isTrue(keyDecrypted)
      })
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

  describe('when a new user signs up', () => {
    let result

    beforeEach(() => {
      subject = new BlockBook()
      return subject.generate(bob.userDetails, bob.password).then(keyPair => {
        result = keyPair
      })
    })

    it('should have a private key', () => {
      assert.equal(result.privateKey[0], '-----BEGIN PGP PRIVATE KEY BLOCK-----')
    })

    it('should have a public key', () => {
      assert.equal(result.publicKey[0], '-----BEGIN PGP PUBLIC KEY BLOCK-----')
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
      return subject.createGroup(state, 'family', alice.password)
      .then((newState) => {
        state = newState
        return subject.post(state, 'some content', ['pals', 'family'], alice.privateKey, alice.password).then(newState => {
          state = newState
        })
      })
    })

    it('should add the post to pals', () => {
      assert.isDefined(state.groups['pals'].posts[0])
      assert.equal(state.groups['pals'].posts[0][0], '-----BEGIN PGP MESSAGE-----')
    })

    it('should add the post to family', () => {
      assert.isDefined(state.groups['family'].posts[0])
      assert.equal(state.groups['family'].posts[0][0], '-----BEGIN PGP MESSAGE-----')
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
      return subject.readContent(bobState.userDetails, aliceState, bob.privateKey, bob.password).then(content => {
        result = content
      })
    })

    it('should be able to read the post', () => {
      assert.equal(result[0], 'some content')
    })
  })

  describe('do the whole process', function () {
    this.timeout(20000)
    let charlieState = {userDetails: {name: 'charlie.id', email: 'charlie@example.com'}}
    const charliePassword = 'charlie-password'
    const charlieGroup = 'mymates'
    const charliePrivateGroup = 'closemates'

    let dannyState = {userDetails: {name: 'danny.id', email: 'danny@example.com'}}
    const dannyPassword = 'danny-password'
    const dannyGroup = 'chums'
    const dannyPrivateGroup = 'family'

    let subject = new BlockBook(1024)

    let charlieContent
    let dannyContent

    before(() => {
      let setupChain = []

      let charlieSetup = subject.generate(charlieState.userDetails, charliePassword)
      .then(keyPair => {
        charlieState.publicKey = keyPair.publicKey
        charlieState.privateKey = keyPair.privateKey
      })
      setupChain.push(charlieSetup)

      let dannySetup = subject.generate(dannyState.userDetails, dannyPassword).then(keyPair => {
        dannyState.publicKey = keyPair.publicKey
        dannyState.privateKey = keyPair.privateKey
      })
      setupChain.push(dannySetup)

      return Promise.all(setupChain).then(() => {
        let groupChain = []
        // Post then add someone
        let charlieGroupSetup = subject.createGroup(charlieState, charlieGroup).then((charlieState) => {
          return subject.createGroup(charlieState, charliePrivateGroup)
        }).then((charlieState) => {
          return subject.post(charlieState, 'Hello world!', [charlieGroup], charlieState.privateKey, charliePassword)
        }).then((charlieState) => {
          return subject.post(charlieState, 'Secret Text', [charliePrivateGroup], charlieState.privateKey, charliePassword)
        }).then((charlieState) => {
          return subject.addToGroup(charlieState, charlieGroup, dannyState.userDetails.name, dannyState.publicKey, charlieState.privateKey, charliePassword)
        }).then(finalState => { charlieState = finalState })
        groupChain.push(charlieGroupSetup)

        // Add someone then post
        let dannyGroupSetup = subject.createGroup(dannyState, dannyGroup)
        .then((dannyState) => {
          return subject.createGroup(dannyState, dannyPrivateGroup)
        }).then((dannyState) => {
          return subject.addToGroup(dannyState, dannyGroup, charlieState.userDetails.name, charlieState.publicKey, dannyState.privateKey, dannyPassword)
        }).then((dannyState) => {
          return subject.post(dannyState, 'Foo Bar!', [dannyGroup], dannyState.privateKey, dannyPassword)
        }).then((dannyState) => {
          return subject.post(dannyState, 'Fus Do Rar', [dannyPrivateGroup], dannyState.privateKey, dannyPassword)
        }).then(finalState => { dannyState = finalState })
        groupChain.push(dannyGroupSetup)

        return Promise.all(groupChain)
      }).then(() => {
        let readChain = []

        let charlieRead = subject.readContent(charlieState.userDetails, dannyState, charlieState.privateKey, charliePassword).then(content => {
          charlieContent = content
        })
        readChain.push(charlieRead)

        let dannyRead = subject.readContent(dannyState.userDetails, charlieState, dannyState.privateKey, dannyPassword).then(content => {
          dannyContent = content
        })
        readChain.push(dannyRead)

        return Promise.all(readChain)
      })
    })

    it('should have danny able to see charlies content', () => {
      assert.equal(dannyContent[0], 'Hello world!')
      assert.equal(dannyContent.length, 1)
    })

    it('should have charlie able to see dannys content', () => {
      assert.equal(charlieContent[0], 'Foo Bar!')
      assert.equal(charlieContent.length, 1)
    })
  })
})()
