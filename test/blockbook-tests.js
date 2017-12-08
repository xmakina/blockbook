/* eslint-env mocha */
(function () {
  let assert = require('chai').assert
  const BlockBook = require('../index').BlockBook
  const KeyPair = require('../index').KeyPair
  const alice = require('./alice.js')
  const bob = require('./bob.js')

  describe('as alice', () => {
    let blockBook = new BlockBook()
    let keyPair = new KeyPair(alice.publicKey, alice.privateKey, alice.password)

    before(() => {
      return blockBook.login({name: alice.userDetails.name, email: alice.userDetails.email, keyPair: keyPair, numBits: 1024}).catch(ex => {})
    })

    it('should log in', () => {
      assert.deepEqual(blockBook.keyPair, keyPair)
    })

    describe('makes post for just bob', () => {
      let post = {}
      before(() => {
        return blockBook.addPost({content: 'hello bob!', key: bob.publicKey}).then(result => {
          post = result
        })
      })

      it('should use bob\'s public key', () => {
        assert.equal(post.publicKey, bob.publicKey)
      })

      it('should encrypt the post', () => {
        assert.equal(post.content[0], '-----BEGIN PGP MESSAGE-----')
      })

      it('should be possible for bob to read the post', () => {
        let bobBlockBook = new BlockBook()
        let bobKeyPair = new KeyPair(bob.publicKey, bob.privateKey, bob.password)
        return bobBlockBook.login({name: bob.userDetails.name, email: bob.userDetails.email, keyPair: bobKeyPair, numBits: 1024}).then(() => {
          return bobBlockBook.readPost(post)
        }).then(clearPost => {
          assert.equal(clearPost, 'hello bob!')
        })
      })
    })

    describe('creates a group', () => {
      let group = {}
      before(() => {
        return blockBook.makeGroup({name: 'Friends'}).then(result => {
          group = result
        })
      })

      it('should have a public key', () => {
        assert.equal(group.publicKey[0], '-----BEGIN PGP PUBLIC KEY BLOCK-----')
      })

      it('should have an encrypted private key', () => {
        assert.equal(group.privateKey[0], '-----BEGIN PGP MESSAGE-----')
      })

      it('should have a name', () => {
        assert.equal(group.name, 'Friends')
      })

      describe('makes a post to the group', () => {
        let groupPost
        before(() => {
          return blockBook.postToGroup({group, content: 'Hello World!'}).then(result => {
            groupPost = result
          })
        })

        it('should encrypt the post', () => {
          assert.equal(groupPost[0], '-----BEGIN PGP MESSAGE-----')
        })

        describe('adds bob to the group', () => {
          let groupMembership
          before(() => {
            return blockBook.addToGroup({group, newMemberPublicKey: bob.publicKey}).then(result => {
              groupMembership = result
            })
          })

          it('should add bob', () => {
            assert.equal(groupMembership.publicKey, bob.publicKey)
          })

          it('should add an encrypted key', () => {
            assert.equal(groupMembership.privateKey[0], '-----BEGIN PGP MESSAGE-----')
          })

          it('should be possible for bob to read the posts', () => {
            let bobBlockBook = new BlockBook()
            let bobKeyPair = new KeyPair(bob.publicKey, bob.privateKey, bob.password)
            return bobBlockBook.login({name: bob.userDetails.name, email: bob.userDetails.email, keyPair: bobKeyPair, numBits: 1024}).then(() => {
              return bobBlockBook.readPostFromGroup({group, groupMembership, groupPost})
            }).then(clearPost => {
              assert.equal(clearPost, 'Hello World!')
            })
          })
        })
      })
    })
  })
})()
