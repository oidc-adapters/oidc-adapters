/* eslint-disable unicorn/numeric-separators-style,quote-props */
import { KeyProvider } from '../src/key-provider.js'
import { DirectGrant } from '../src/direct-grant.js'

describe('key-provider.ts', function () {
  it('should retrieve PEM key from allowed issuer', async () => {
    const directGrant = new DirectGrant({
      authority: 'http://localhost:8109/realms/master',
      client_id: 'admin-cli'
    })

    const tokenReponseJson = await directGrant.password('admin', 'admin')
    const accessToken = tokenReponseJson?.access_token
    if (!accessToken) throw new Error('Invalid keycloak token')

    const keyProvider = new KeyProvider({ allowedIssuers: ['http://localhost:8109/realms/master'] })
    const publicKey = await keyProvider.getPublicKey(accessToken)

    expect(publicKey).toBeDefined()
  })

  it('should retrieve PEM key from allowed issuer (regexp)', async () => {
    const directGrant = new DirectGrant({
      authority: 'http://localhost:8109/realms/master',
      client_id: 'admin-cli'
    })

    const tokenReponseJson = await directGrant.password('admin', 'admin')
    const accessToken = tokenReponseJson?.access_token
    if (!accessToken) throw new Error('Invalid keycloak token')

    const keyProvider = new KeyProvider({ allowedIssuers: [/http:\/\/localhost:8109\/realms\/.*?/] })
    const publicKey = await keyProvider.getPublicKey(accessToken)

    expect(publicKey).toBeDefined()
  })

  it('should not retrieve PEM key from not allowed issuer', async () => {
    const body = new URLSearchParams()
    body.append('client_id', 'admin-cli')
    body.append('username', 'admin')
    body.append('password', 'admin')
    body.append('grant_type', 'password')

    const tokenResponse = await fetch('http://localhost:8109/realms/master/protocol/openid-connect/token', {
      method: 'post',
      body
    })
    const tokenReponseJson = await tokenResponse.json() as { access_token: string }
    const accessToken = tokenReponseJson?.access_token
    if (!accessToken) throw new Error('Invalid keycloak token')

    const keyProvider = new KeyProvider({ allowedIssuers: ['http://localhost:8110/realms/master'] })
    await expect(keyProvider.getPublicKey(accessToken)).rejects.toThrow('Token issuer "http://localhost:8109/realms/master" is not allowed')
  })

  it('should not retrieve PEM key from not allowed issuer (regex)', async () => {
    const body = new URLSearchParams()
    body.append('client_id', 'admin-cli')
    body.append('username', 'admin')
    body.append('password', 'admin')
    body.append('grant_type', 'password')

    const tokenResponse = await fetch('http://localhost:8109/realms/master/protocol/openid-connect/token', {
      method: 'post',
      body
    })
    const tokenReponseJson = await tokenResponse.json() as { access_token: string }
    const accessToken = tokenReponseJson?.access_token
    if (!accessToken) throw new Error('Invalid keycloak token')

    const keyProvider = new KeyProvider({ allowedIssuers: ['http://localhost:8110/realms/another', /http:\/\/localhost:8000\/.*/] })
    await expect(keyProvider.getPublicKey(accessToken)).rejects.toThrow('Token issuer "http://localhost:8109/realms/master" is not allowed')
  })
})
