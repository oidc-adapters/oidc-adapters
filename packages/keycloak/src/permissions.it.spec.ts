import type { FetchUmaTicketOptions } from './permissions.js'
import { fetchUmaTicketPermissionsToken, KeycloakPermissionsProvider } from './permissions.js'
import { DirectGrant } from '@oidc-adapters/core'
import { expect } from '@jest/globals'

describe('fetchUmaTicket (IT)', function () {
  it('should give umaTicket token', async () => {
    const directGrant = new DirectGrant({
      client_id: 'app-authorization-services-test',
      client_secret: 'etkjHLXBRPpYSdebPqLM9XrPvkOzbv2d',
      scope: 'openid',
      authority: 'http://localhost:8109/realms/keycloak-test'
    })

    const tokenReponseJson = await directGrant.password('admin', 'admin')

    const umaTicket = await fetchUmaTicketPermissionsToken({ token: tokenReponseJson.access_token })
    expect(umaTicket).toBeDefined()
    expect(umaTicket.authorization).toBeDefined()
    expect(umaTicket.authorization?.permissions.length).toEqual(4)
    for (const permission of umaTicket.authorization!.permissions) {
      if (permission.rsname !== 'Default Resource') {
        // eslint-disable-next-line jest/no-conditional-expect
        expect(new Set(permission.scopes)).toEqual(new Set(['create', 'read', 'update', 'delete']))
      }
    }
  })

  it('should give umaTicket token with resource filter', async () => {
    const directGrant = new DirectGrant({
      client_id: 'app-authorization-services-test',
      client_secret: 'etkjHLXBRPpYSdebPqLM9XrPvkOzbv2d',
      scope: 'openid',
      authority: 'http://localhost:8109/realms/keycloak-test'
    })

    const tokenReponseJson = await directGrant.password('admin', 'admin')

    const umaTicket = await fetchUmaTicketPermissionsToken({
      token: tokenReponseJson.access_token,
      permission: 'resource1'
    })
    expect(umaTicket).toBeDefined()
    expect(umaTicket.authorization?.permissions.length).toEqual(1)
    for (const permission of umaTicket.authorization!.permissions) {
      expect(new Set(permission.scopes)).toEqual(new Set(['create', 'read', 'update', 'delete']))
    }
  })

  it('should give umaTicket token with scope filter', async () => {
    const directGrant = new DirectGrant({
      client_id: 'app-authorization-services-test',
      client_secret: 'etkjHLXBRPpYSdebPqLM9XrPvkOzbv2d',
      scope: 'openid',
      authority: 'http://localhost:8109/realms/keycloak-test'
    })

    const tokenReponseJson = await directGrant.password('admin', 'admin')

    const umaTicket = await fetchUmaTicketPermissionsToken({
      token: tokenReponseJson.access_token,
      permission: '#read'
    })
    expect(umaTicket).toBeDefined()
    expect(umaTicket.authorization?.permissions.length).toEqual(3)
    for (const permission of umaTicket.authorization!.permissions) {
      expect(permission.scopes).toEqual(['read'])
    }
  })
})

const variants: { describe: string, options?: FetchUmaTicketOptions }[] = [
  {
    describe: 'With no option'
  },
  {
    describe: ' With responseMode=\'decision\' option',
    options: {
      responseMode: 'decision'
    }
  }
]

describe('KeycloakPermissionsProvider', function () {
  for (const variant of variants) {
    // eslint-disable-next-line jest/valid-title
    describe(variant.describe, () => {
      it('should check permissions', async () => {
        const directGrant = new DirectGrant({
          client_id: 'app-authorization-services-test',
          client_secret: 'etkjHLXBRPpYSdebPqLM9XrPvkOzbv2d',
          scope: 'openid',
          authority: 'http://localhost:8109/realms/keycloak-test'
        })

        const tokenReponseJson = await directGrant.password('admin', 'admin')

        const permissionsProvider = new KeycloakPermissionsProvider({ token: tokenReponseJson.access_token, ...variant.options })

        expect(await permissionsProvider.hasPermission('resource1#delete')).toBe(true)
        expect(await permissionsProvider.hasPermission('resource2#delete')).toBe(true)
        expect(await permissionsProvider.hasPermission('dummy')).toBe(false)
      })

      it('should check permissions using additional permission filter', async () => {
        const directGrant = new DirectGrant({
          client_id: 'app-authorization-services-test',
          client_secret: 'etkjHLXBRPpYSdebPqLM9XrPvkOzbv2d',
          scope: 'openid',
          authority: 'http://localhost:8109/realms/keycloak-test'
        })

        const tokenReponseJson = await directGrant.password('admin', 'admin')

        const permissionsProvider = new KeycloakPermissionsProvider({
          token: tokenReponseJson.access_token,
          permission: 'resource2',
          ...variant.options
        })

        expect(await permissionsProvider.hasPermission('resource1#delete')).toBe(variant.options?.responseMode === 'decision')
        expect(await permissionsProvider.hasPermission('resource2#delete')).toBe(true) // Only resource2 is included in permissions provider
        expect(await permissionsProvider.hasPermission('dummy')).toBe(false)
      })

      it('should check permissions (as user)', async () => {
        const directGrant = new DirectGrant({
          client_id: 'app-authorization-services-test',
          client_secret: 'etkjHLXBRPpYSdebPqLM9XrPvkOzbv2d',
          scope: 'openid',
          authority: 'http://localhost:8109/realms/keycloak-test'
        })

        const tokenReponseJson = await directGrant.password('user', 'user')

        const permissionsProvider = new KeycloakPermissionsProvider({ token: tokenReponseJson.access_token, ...variant.options })

        expect(await permissionsProvider.hasPermission('resource1#read')).toBe(true)
        expect(await permissionsProvider.hasPermission('resource2#read')).toBe(true)
        expect(await permissionsProvider.hasPermission('resource1#delete')).toBe(false)
        expect(await permissionsProvider.hasPermission('resource2#delete')).toBe(false)
        expect(await permissionsProvider.hasPermission('dummy')).toBe(false)
      })

      it('should check permissions for resource', async () => {
        const directGrant = new DirectGrant({
          client_id: 'app-authorization-services-test',
          client_secret: 'etkjHLXBRPpYSdebPqLM9XrPvkOzbv2d',
          scope: 'openid',
          authority: 'http://localhost:8109/realms/keycloak-test'
        })

        const tokenReponseJson = await directGrant.password('admin', 'admin')

        const permissionsProvider = new KeycloakPermissionsProvider({ token: tokenReponseJson.access_token, ...variant.options })

        expect(await permissionsProvider.hasResourcePermission('resource1', 'delete')).toBe(true)
        expect(await permissionsProvider.hasResourcePermission('resource2', 'delete')).toBe(true)
        expect(await permissionsProvider.hasResourcePermission('dummy', 'delete')).toBe(false)
      })

      it('should get permissions', async () => {
        const directGrant = new DirectGrant({
          client_id: 'app-authorization-services-test',
          client_secret: 'etkjHLXBRPpYSdebPqLM9XrPvkOzbv2d',
          scope: 'openid',
          authority: 'http://localhost:8109/realms/keycloak-test'
        })

        const tokenReponseJson = await directGrant.password('admin', 'admin')

        const permissionsProvider = new KeycloakPermissionsProvider({ token: tokenReponseJson.access_token, ...variant.options })

        expect(new Set(await permissionsProvider.getPermissions())).toEqual(new Set([
          'resource1#create',
          'resource1#read',
          'resource1#update',
          'resource1#delete',
          'resource2#create',
          'resource2#read',
          'resource2#update',
          'resource2#delete',
          'admin-resource#create',
          'admin-resource#read',
          'admin-resource#update',
          'admin-resource#delete'
        ]))
      })

      it('should get permissions for resource', async () => {
        const directGrant = new DirectGrant({
          client_id: 'app-authorization-services-test',
          client_secret: 'etkjHLXBRPpYSdebPqLM9XrPvkOzbv2d',
          scope: 'openid',
          authority: 'http://localhost:8109/realms/keycloak-test'
        })

        const tokenReponseJson = await directGrant.password('admin', 'admin')

        const permissionsProvider = new KeycloakPermissionsProvider({ token: tokenReponseJson.access_token, ...variant.options })

        expect(new Set(await permissionsProvider.getResourcePermissions('resource1'))).toEqual(new Set([
          'create',
          'read',
          'update',
          'delete'
        ]))

        expect(new Set(await permissionsProvider.getResourcePermissions('resource2'))).toEqual(new Set([
          'create',
          'read',
          'update',
          'delete'
        ]))

        expect(await permissionsProvider.getResourcePermissions('dummy')).toHaveLength(0)
      })
    })
  }
})
