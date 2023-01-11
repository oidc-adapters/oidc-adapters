import type { RolesProvider } from '@oidc-adapters/core/src/index.js'

export interface KeycloakTokenClaims {
  realm_access?: {
    roles?: string[]
  }
  resource_access?: Record<string, { roles?: string[] }>
}

const realmKey = 'realm'

export class KeycloakRolesProvider implements RolesProvider {
  constructor (private token: KeycloakTokenClaims, private app?: string) {
  }

  hasRole (role: string): boolean {
    const split = role.split(':')
    if (split.length <= 1) {
      return this.hasRoleImpl(split[0])
    }
    return this.hasRoleImpl(split[1], split[0])
  }

  getRoles (): string[] {
    const roles: string[] = []

    if (this.token?.realm_access?.roles !== undefined) {
      for (const role of this.token.realm_access.roles) {
        if (this.app === realmKey) {
          roles.push(role)
        } else {
          roles.push(`${realmKey}:${role}`)
        }
      }
    }

    if (this.token?.resource_access !== undefined) {
      for (const [app, appRoles] of Object.entries(this.token.resource_access)) {
        if (appRoles.roles !== undefined) {
          for (const role of appRoles.roles) {
            if (this.app === app) {
              roles.push(role)
            } else {
              roles.push(`${app}:${role}`)
            }
          }
        }
      }
    }

    return roles
  }

  private hasRoleImpl (role: string, app = this.app) {
    if (app === realmKey) {
      return this.hasRealmRole(role)
    }

    if (app === undefined) {
      return false
    }

    return this.hasAppRole(role, app)
  }

  private hasRealmRole (role: string) {
    if (this.token?.realm_access?.roles === undefined) {
      return false
    }

    return this.token.realm_access.roles.includes(role)
  }

  private hasAppRole (role: string, app: string) {
    if (this.token?.resource_access === undefined) {
      return false
    }

    const appRoles = this.token.resource_access[app]
    if (appRoles?.roles === undefined) {
      return false
    }

    return appRoles.roles.includes(role)
  }
}
