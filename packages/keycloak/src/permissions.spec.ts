import type { KeycloakUmaTicketTokenClaims } from './permissions.js'
import { KeycloakUmaTicketPermissionsProvider } from './permissions.js'

describe('Permissions', function () {
  const token: KeycloakUmaTicketTokenClaims = {
    authorization: {
      permissions: [
        { rsid: 'id1', rsname: 'resource1', scopes: ['create', 'read', 'update', 'delete'] },
        { rsid: 'id2', rsname: 'resource2', scopes: ['read'] }
      ]
    }
  }

  it('should get all permissions', () => {
    const accessor = new KeycloakUmaTicketPermissionsProvider(token)
    expect(accessor.getPermissions()).toEqual(['resource1#create', 'resource1#read', 'resource1#update', 'resource1#delete', 'resource2#read'])
  })

  it('should get all permissions for a resource', () => {
    const accessor = new KeycloakUmaTicketPermissionsProvider(token)
    expect(accessor.getResourcePermissions('resource1')).toEqual(['create', 'read', 'update', 'delete'])
    expect(accessor.getResourcePermissions('resource2')).toEqual(['read'])
    expect(accessor.getResourcePermissions('dummy')).toEqual([])
  })

  it('should check permissions', () => {
    const accessor = new KeycloakUmaTicketPermissionsProvider(token)
    expect(accessor.hasPermission('resource1#read')).toBe(true)
    expect(accessor.hasPermission('resource2#read')).toBe(true)
    expect(accessor.hasPermission('resource2#delete')).toBe(false)
    expect(accessor.hasPermission('dummy#read')).toBe(false)
  })

  it('should check permissions for a resource', () => {
    const accessor = new KeycloakUmaTicketPermissionsProvider(token)
    expect(accessor.hasResourcePermission('resource1', 'read')).toBe(true)
    expect(accessor.hasResourcePermission('resource2', 'read')).toBe(true)
    expect(accessor.hasResourcePermission('resource2', 'delete')).toBe(false)
    expect(accessor.hasResourcePermission('dummy', 'read')).toBe(false)
  })
})
