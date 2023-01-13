import type { RolesProvider } from '@oidc-adapters/core/src/index.js'
import type { IdTokenClaims } from 'oidc-client-ts'

export interface KeycloakTokenClaims extends Partial<IdTokenClaims> {
  realm_access?: {
    roles?: string[]
  }
  resource_access?: Record<string, { roles?: string[] }>
}

const realmKey = 'realm'

export class KeycloakRolesProvider implements RolesProvider {
  private rolesSet: Set<string> = new Set()
  private hasRolesSet: Set<string> = new Set()

  constructor (private token: KeycloakTokenClaims, private app = token.azp) {
    if (this.token?.realm_access?.roles !== undefined) {
      for (const role of this.token.realm_access.roles) {
        this.hasRolesSet.add(`${realmKey}:${role}`)
        if (this.app === realmKey) {
          this.rolesSet.add(role)
          this.hasRolesSet.add(role)
        } else {
          this.rolesSet.add(`${realmKey}:${role}`)
        }
      }
    }

    if (this.token?.resource_access !== undefined) {
      for (const [app, appRoles] of Object.entries(this.token.resource_access)) {
        if (appRoles.roles !== undefined) {
          for (const role of appRoles.roles) {
            this.hasRolesSet.add(`${app}:${role}`)
            if (this.app === app) {
              this.rolesSet.add(role)
              this.hasRolesSet.add(role)
            } else {
              this.rolesSet.add(`${app}:${role}`)
            }
          }
        }
      }
    }
  }

  hasRole (role: string): boolean {
    return this.hasRolesSet.has(role)
  }

  getRoles (): string[] {
    return [...this.rolesSet]
  }
}
