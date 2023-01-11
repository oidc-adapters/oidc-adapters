/**
 * @group unit
 */
import { generateKeyPair } from 'node:crypto'
import { promisify } from 'node:util'
import Config from '../src/middleware/auth-utils/config.js'

const generateKeyPairP = promisify(generateKeyPair)

it('Config#configure', () => {
  const cfg = new Config({ realm: 'test-realm' })

  expect(cfg.realm).toEqual('test-realm')
})

it('Config#configure with boolean', () => {
  const cfg = new Config({ public: true })

  expect(cfg.public).toBe(true)
})

/* eslint-disable no-template-curly-in-string */
it('Config#configure with env variable reference not set', () => {
  const cfg = new Config({ realm: '${env.NOT_SET}' })

  expect(cfg.realm).toEqual('')
})

it('Config#configure with env variable reference not set with fallback', () => {
  const cfg = new Config({ realm: '${env.NOT_SET:fallback}' })

  expect(cfg.realm).toEqual('fallback')
})

it('Config#configure with env variable reference set', () => {
  const cfg = new Config({ realm: '${env.USER}' })

  expect(cfg.realm).toEqual(process.env.USER)
})

it('Config#configure with env variable reference set with fallback', () => {
  const cfg = new Config({ realm: '${env.USER:fallback}' })

  expect(cfg.realm).toEqual(process.env.USER)
})

it('Config#configure with realm-public-key', async () => {
  const { publicKey } = await generateKeyPairP('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: ''
    }
  })

  const plainKey = publicKey.split(/\r?\n/).filter(item => item && !item.startsWith('---')).join('')
  const cfg = new Config({ 'realm-public-key': plainKey })

  expect(cfg.publicKey).toEqual(publicKey.replace(/RSA PUBLIC/g, 'PUBLIC').replace(/\r/g, ''))
})

it('Config#configure with realmPublicKey', async () => {
  const { publicKey } = await generateKeyPairP('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: ''
    }
  })

  const plainKey = publicKey.split(/\r?\n/).filter(item => item && !item.startsWith('---')).join('')
  const cfg = new Config({ realmPublicKey: plainKey })

  // Added this due to the upgrades in rsa-compat headers
  expect(cfg.publicKey).toEqual(publicKey.replace(/RSA PUBLIC/g, 'PUBLIC').replace(/\r/g, ''))
})
