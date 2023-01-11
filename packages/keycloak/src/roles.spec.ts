import type { KeycloakTokenClaims } from './roles.js'
import { KeycloakRolesProvider } from './roles.js'

describe('Roles', function () {
  const token: KeycloakTokenClaims = {
    realm_access: {
      roles: ['role-realm-1', 'role-realm-2']
    },
    resource_access: {
      app1: { roles: ['role-app1-A', 'role-app1-B'] },
      app2: { roles: ['role-app2-A', 'role-app2-B'] }
    }
  }

  it('should get all roles prefixed with app', () => {
    const accessor = new KeycloakRolesProvider(token)
    expect(accessor.getRoles()).toEqual(['realm:role-realm-1', 'realm:role-realm-2', 'app1:role-app1-A', 'app1:role-app1-B', 'app2:role-app2-A', 'app2:role-app2-B'])
  })

  it('should get all roles prefixed with app but default app', () => {
    const accessor = new KeycloakRolesProvider(token, 'app1')
    expect(accessor.getRoles()).toEqual(['realm:role-realm-1', 'realm:role-realm-2', 'role-app1-A', 'role-app1-B', 'app2:role-app2-A', 'app2:role-app2-B'])
  })

  it('should check single role', () => {
    const accessor = new KeycloakRolesProvider(token)
    expect(accessor.hasRole('role-app1-A')).toBe(false)
    expect(accessor.hasRole('app1:role-app1-A')).toBe(true)

    expect(accessor.hasRole('role-app2-A')).toBe(false)
    expect(accessor.hasRole('app2:role-app2-A')).toBe(true)
  })

  it('should check single role without default app prefix', () => {
    const accessor = new KeycloakRolesProvider(token, 'app1')
    expect(accessor.hasRole('role-app1-A')).toBe(true)
    expect(accessor.hasRole('app1:role-app1-A')).toBe(true)

    expect(accessor.hasRole('role-app2-A')).toBe(false)
    expect(accessor.hasRole('app2:role-app2-A')).toBe(true)
  })

  it('should check missing role', () => {
    const accessor = new KeycloakRolesProvider(token)
    expect(accessor.hasRole('dummy')).toBe(false)
    expect(accessor.hasRole('app1:dummy')).toBe(false)
    expect(accessor.hasRole('realm:dummy')).toBe(false)
  })
})
