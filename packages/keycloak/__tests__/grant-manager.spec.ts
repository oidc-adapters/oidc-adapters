/**
 * @group integration
 */
import { mock } from 'jest-mock-extended'
import type Token from '../src/middleware/auth-utils/token.js'
import type { TokenContent } from '../src/middleware/auth-utils/token.js'
import type Grant from '../src/middleware/auth-utils/grant.js'
import fetchMock from 'fetch-mock'
import { dummyReply } from './utils/helper.js'
import isEqual from 'lodash/isEqual.js'
import { setTimeout } from 'node:timers/promises'
import { buildGrantManager } from './utils/grant.js'

afterAll(() => {
  fetchMock.restore()
})

it('GrantManager with empty configuration', () => {
  expect(() => buildGrantManager(undefined as unknown as string)).toThrow()
})

it('GrantManager with rogue configuration', () => {
  const rogueManager = buildGrantManager({})

  expect(rogueManager.clientId).toBeUndefined()
  expect(rogueManager.publicKey).toBeUndefined()
  expect(rogueManager.secret).toBeUndefined()
})

it('GrantManager in public mode should be able to obtain a grant', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-public.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(grant.access_token).toBeDefined()
})

it('GrantManager in public mode should be able to obtain a raw grant', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-public.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(grant.toString()).toBeDefined()
})

it('GrantManager in public mode with public key configured should be able to obtain a grant', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-with-public-key.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(grant.access_token).toBeDefined()
})

it('GrantManager in public mode should be able to refresh a grant', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-with-public-key.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(manager.isGrantRefreshable(grant)).toBe(true)
})

it('GrantManager should return empty with public key configured but invalid signature', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-with-public-key.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')

  grant.access_token!.signature = Buffer.from('da39a3ee5e6b4b0d3255bfef95601890afd80709', 'ascii')
  await expect(() => manager.validateToken(grant.access_token, 'Bearer')).rejects.toThrow('invalid token (signature)')
})

it('GrantManager in public mode should be able to get userinfo', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-public.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  const user = await manager.userInfo(grant.access_token!)
  expect(user.preferred_username).toEqual('test-user')
})

it('GrantManager in public mode should fail if audience of ID token is not valid', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-public.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.id_token!.content.aud = []
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (wrong audience)')
})

it('GrantManager in public mode should fail if audience of ID token is not valid with a dummy client in single array', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-public.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.id_token!.content.aud = ['public-client-dummy']
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (wrong audience)')
})

it('GrantManager in public mode should fail if audience of ID token is not valid with a dummy client in strings', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-public.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.id_token!.content.aud = 'public-client-dummy'
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (wrong audience)')
})

it('GrantManager in public mode should fail if authorized party for ID token is not valid', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-public.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.id_token!.content.azp = undefined
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (authorized party should match client id)')
})

it('GrantManager in public mode should fail if audience of Access token is not valid', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-public.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.content.aud = []
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (wrong audience)')
})

const manager = buildGrantManager('./fixtures/auth-utils/keycloak-confidential.json')
it('GrantManager in confidential mode should be able to get userinfo', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  const user = await manager.userInfo(grant.access_token!)
  expect(user.preferred_username).toEqual('test-user')
})

it('GrantManager in confidential mode should be able to obtain a grant', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(grant.access_token).toBeDefined()
})

it('GrantManager in confidential mode should be able to refresh a grant', async () => {
  let grant = await manager.obtainDirectly('test-user', 'tiger')
  await setTimeout(3000)
  expect(manager.isGrantRefreshable(grant)).toBe(true)
  expect(grant.access_token).toBeDefined()
  const originalAccessToken = grant.access_token!
  grant = await manager.ensureFreshness(grant)
  expect(grant.access_token).toBeDefined()
  expect(grant.access_token!.token).not.toEqual(originalAccessToken.token)
})

it('GrantManager in confidential mode should be able to validate a valid token', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  const originalAccessToken = grant.access_token
  const token = await manager.validateAccessToken(grant.access_token!)
  expect(token).toBeDefined()
  expect(token).toEqual(originalAccessToken)
})

it('GrantManager in confidential mode should be able to validate an invalid token', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  await setTimeout(3000)
  const result = await manager.validateAccessToken(grant.access_token!)
  expect(result).toBe(false)
})

it('GrantManager in confidential mode should be able to validate a token has an invalid signature', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.token = grant.access_token!.token.replace(/(.+?\..+?\.).*/, '$1.InvalidSignatureIsHereAgain')
  const result = await manager.validateAccessToken(grant.access_token!)
  expect(result).toBe(false)
})

it('GrantManager in confidential mode should be able to validate a valid token string', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  const originalAccessToken = grant.access_token!.token
  const token = await manager.validateAccessToken(grant.access_token!.token)
  expect(token).toBeDefined()
  expect(token).toEqual(originalAccessToken)
})

it('GrantManager in confidential mode should be able to validate an invalid token string', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  await setTimeout(3000)
  const result = await manager.validateAccessToken(grant.access_token!.token)
  expect(result).toBe(false)
})

it('GrantManager in confidential mode should be able to obtain a service account grant', async () => {
  const grant = await manager.obtainFromClientCredentials()
  await setTimeout(3000)
  const result = await manager.validateAccessToken(grant.access_token!.token)
  expect(result).toBe(false)
})

it('GrantManager in confidential mode should fail if audience of ID token is not valid', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.id_token!.content.aud = undefined
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (wrong audience)')
})

it('GrantManager in confidential mode should fail if audience of ID token is not valid with a dummy client in strings', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-public.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.id_token!.content.aud = 'confidential-client-dummy'
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (wrong audience)')
})

it('GrantManager in confidential mode should fail if audience of ID token is not valid with a dummy client in single array', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-public.json')
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.id_token!.content.aud = ['confidential-client-dummy']
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (wrong audience)')
})

it('GrantManager in confidential mode should fail if authorized party for ID token is not valid', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.id_token!.content.azp = undefined
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (authorized party should match client id)')
})

it('GrantManager in confidential mode should fail if audience of Access token is not valid', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.content.aud = undefined
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (wrong audience)')
})

it('GrantManager should be able to validate tokens in a grant', async () => {
  let grant = await manager.obtainDirectly('test-user', 'tiger')
  const originalAccessToken = grant.access_token
  const originalRefreshToken = grant.refresh_token
  const orginalIdToken = grant.id_token
  grant = await manager.validateGrant(grant)

  expect(grant.access_token).toBeDefined()
  expect(grant.access_token).toEqual(originalAccessToken)
  expect(grant.refresh_token).toEqual(originalRefreshToken)
  expect(grant.id_token).toEqual(orginalIdToken)
})

it('GrantManager should be able to remove invalid tokens from a grant', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.signature = Buffer.from('this signature is invalid')
  grant.refresh_token!.signature = Buffer.from('this signature is also invalid')
  grant.id_token!.signature = Buffer.from('this signature is still invalid')

  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (public key signature)')
})

it('GrantManager should reject with token missing error when bearer only', async () => {
  const originalBearerOnly = manager.bearerOnly
  try {
    manager.bearerOnly = true
    await expect(() => manager.createGrant('{ }')).rejects.toThrow('Grant validation failed. Reason: invalid token (missing)')
  } finally {
    manager.bearerOnly = originalBearerOnly
  }
})

it('GrantManager should not be able to refresh a grant when bearer only', async () => {
  const originalBearerOnly = manager.bearerOnly
  try {
    manager.bearerOnly = true
    expect(manager.isGrantRefreshable({ refresh_token: mock<Token>() })).toBe(false)
  } finally {
    manager.bearerOnly = originalBearerOnly
  }
})

it('GrantManager should reject with refresh token missing error', async () => {
  const grant = mock<Grant>()
  grant.isExpired.mockReturnValue(true)
  grant.refresh_token = undefined

  await expect(() => manager.ensureFreshness(grant)).rejects.toThrow('Unable to refresh without a refresh token')
})

it('GrantManager validate empty access token', async () => {
  const result = await manager.validateAccessToken('')
  expect(result).toBe(false)
})

it('GrantManager return user realm role', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(grant.access_token!.hasRealmRole('user')).toBe(true)
})

it('GrantManager validate non existent role', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(grant.access_token!.hasRealmRole('')).toBe(false)
})

it('GrantManager should be false for user with no realm level roles', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.content.realm_access = {} as unknown as undefined
  expect(grant.access_token!.hasRealmRole('test')).toBe(false)
})

it('GrantManager validate non existent role app', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(grant.access_token!.hasRole('')).toBe(false)
})

it('GrantManager validate existent role app', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(grant.access_token!.hasRole('test')).toBe(true)
})

it('GrantManager validate role app with empty clientId', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.clientId = ''
  expect(grant.access_token!.hasRole('test')).toBe(false)
})

it('GrantManager validate empty role app', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(grant.access_token!.hasApplicationRole('', '')).toBe(false)
})

it('GrantManager return user realm role based on realm name', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(grant.access_token!.hasRole('realm:user')).toBe(true)
})

it('GrantManager in confidential mode should validate access token', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  const result = await manager.validateAccessToken(grant.access_token!)
  expect(result).toEqual(grant.access_token)
})

it('GrantManager should be able to remove expired access_token token and keep others', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.content.exp = 0
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (expired)')
})

it('GrantManager should raise an error when trying to obtain from code with rogue params', async () => {
  await expect(() => manager.obtainFromCode(mock(), '', '', '')).rejects.toThrow('400:Bad Request')
})

it('GrantManager should be able to validate invalid ISS', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.content.iss = 'http://wrongiss.com'
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (wrong ISS)')
})

it('GrantManager should be able to validate invalid iat', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.content.iat = -5
  await expect(() => manager.validateGrant(grant)).rejects.toThrow('Grant validation failed. Reason: invalid token (stale token)')
})

it('GrantManager should be ensure that a grant is fresh', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  const result = await manager.ensureFreshness(grant)
  expect(result).toStrictEqual(grant)
})

it('GrantManager should raise an error when access token and refresh token do not exist', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token = undefined
  grant.refresh_token = undefined
  await expect(() => manager.ensureFreshness(grant)).rejects.toThrow('Unable to refresh without a refresh token')
})

it('GrantManager should validate unsigned token', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.signed = ''
  await expect(() => manager.validateToken(grant.access_token, 'Bearer')).rejects.toThrow('invalid token (not signed)')
})

it('GrantManager should not validate token with wrong type', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  await expect(() => manager.validateToken(grant.access_token, 'Refresh')).rejects.toThrow('invalid token (wrong type)')
})

it('GrantManager should fail to load public key when kid is empty', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.header.kid = undefined as unknown as string
  await expect(() => manager.validateToken(grant.access_token, 'Bearer')).rejects.toThrow('invalid token (missing kid)')
})

it('GrantManager should fail with invalid signature', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.signature = Buffer.from('da39a3ee5e6b4b0d3255bfef95601890afd80709')
  await expect(() => manager.validateToken(grant.access_token, 'Bearer')).rejects.toThrow('invalid token (public key signature)')
})

it('GrantManager should return false when resource_access is undefined', async () => {
  const grant = await manager.obtainDirectly('test-user', 'tiger')
  grant.access_token!.content = {} as unknown as TokenContent
  expect(grant.access_token!.hasApplicationRole('test', 'role')).toBe(false)
})

it('GrantManager#validateToken returns undefined for an invalid token', async () => {
  const expiredToken = mock<Token>()
  expiredToken.isExpired.mockReturnValue(true)

  const unsignedToken = mock<Token>()
  expiredToken.isExpired.mockReturnValue(false)

  const notBeforeToken = mock<Token>()
  notBeforeToken.isExpired.mockReturnValue(false)
  notBeforeToken.signed = 'signature'
  notBeforeToken.content = { iat: -1 } as TokenContent

  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-https.json')
  const tokens = [
    undefined,
    expiredToken,
    unsignedToken,
    notBeforeToken
  ]

  for (const token of tokens) {
    await expect(() => manager.validateToken(token as Token, 'Bearer')).rejects.toThrow()
  }
})

it('GrantManager#obtainDirectly should work with https', async () => {
  fetchMock.mock({
    url: 'https://localhost:8080/realms/nodejs-test/protocol/openid-connect/token',
    method: 'post',
    functionMatcher (string: string, options): boolean {
      if (options.body instanceof URLSearchParams) {
        return isEqual(Object.fromEntries(options.body), {
          client_id: 'public-client',
          username: 'test-user',
          password: 'tiger',
          grant_type: 'password',
          scope: 'openid'
        })
      }

      return false
    }
  }, { status: 204, body: dummyReply })

  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-https.json', { keepServerUrl: true })
  manager.validateToken = async (token) => { return token! }
  manager.ensureFreshness = async (token) => { return token }

  const grant = await manager.obtainDirectly('test-user', 'tiger')
  expect(grant.access_token!.token).toEqual(dummyReply.access_token)
})

it('GrantManager#ensureFreshness should fetch new access token with client id', async () => {
  const refreshedToken = {
    access_token: 'some.access.token',
    expires_in: 30,
    refresh_expires_in: 1800,
    refresh_token: 'i-Am-The-Refresh-Token',
    token_type: 'bearer',
    id_token: 'some-id-token',
    'not-before-policy': 1_462_208_947,
    session_state: 'ess-sion-tat-se'
  }

  fetchMock.post('http://localhost:8180', 204)
  fetchMock.mock({
    url: 'http://localhost:8180/realms/nodejs-test-mock/protocol/openid-connect/token',
    method: 'post',
    functionMatcher (string: string, options): boolean {
      if (options.body instanceof URLSearchParams) {
        return isEqual(Object.fromEntries(options.body), {
          grant_type: 'refresh_token',
          client_id: 'public-client',
          refresh_token: 'i-Am-The-Refresh-Token'
        })
      }

      return false
    }
  }, { status: 204, body: refreshedToken })

  const grant = mock<Grant>()
  grant.isExpired.mockReturnValue(true)
  const refreshToken = mock<Token>()
  refreshToken.token = 'i-Am-The-Refresh-Token'
  refreshToken.isExpired.mockReturnValue(false)
  grant.refresh_token = refreshToken

  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-public-mock.json', { keepServerUrl: true })
  manager.createGrant = (token) => { return token as Promise<Grant> }

  const newGrant = await manager.ensureFreshness(grant)
  expect(newGrant).toEqual(refreshedToken)
})
