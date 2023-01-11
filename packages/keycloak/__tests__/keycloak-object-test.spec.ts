/**
 * @group unit
 */
import type { AdapterConfig } from '../src/index.js'
import Keycloak from '../src/index.js'
import { MemoryStore } from 'express-session'
import type { ConfigInput } from '../src/middleware/auth-utils/config.js'

describe('Keycloak instance', () => {
  it('Should raise an error when no configuration is provided.', () => {
    expect(() => new Keycloak(undefined as unknown as AdapterConfig)).toThrow('Adapter configuration must be provided.')
  })

  const kcConfig: ConfigInput = {
    realm: 'test-realm',
    'auth-server-url': 'http://localhost:8080',
    resource: 'nodejs-connect',
    'public-client': true
  }

  const memoryStore = new MemoryStore()
  const kc = new Keycloak({ store: memoryStore, scope: 'offline_support' }, kcConfig)

  it('Should verify the realm name of the config object.', () => {
    expect(kc.config.realm).toEqual('test-realm')
  })

  it('Should verify if login URL has the configured realm.', () => {
    expect(kc.loginUrl('uuid', 'redirectUrl').indexOf(kc.config.realm) > 0).toBe(true)
  })

  it('Should verify if login URL has the custom scope value.', () => {
    expect(kc.loginUrl('uuid', 'redirectUrl').indexOf(kc.adapterConfig.scope!) > 0).toBe(true)
  })

  it('Should verify if login URL has the default scope value.', () => {
    expect(kc.loginUrl('uuid', 'redirectUrl').indexOf('openid') > 0).toBe(true)
  })

  it('Should verify if logout URL has the configured realm.', () => {
    expect(kc.logoutUrl('uuid', 'redirectUrl').indexOf(kc.config.realm) > 0).toBe(true)
  })

  it('Should produce correct account url.', () => {
    expect(kc.accountUrl()).toEqual('http://localhost:8080/realms/test-realm/account')
  })
})
