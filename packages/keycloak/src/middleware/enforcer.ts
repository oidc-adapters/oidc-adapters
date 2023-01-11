import type Keycloak from '../index.js'
import type { NextFunction, Request, Response } from 'express'
import type { AuthzPermission, AuthzRequest } from './auth-utils/grant-manager.js'

function handlePermissions (permissions: string[], callback: (resource: string, scope: string | undefined) => false | void) {
  for (const permission of permissions) {
    const [resource, scope] = permission.split(':')

    if (resource) {
      const r = callback(resource, scope)

      if (r === false) {
        return r
      }
    }
  }

  return true
}

export interface EnforcerConfig {
  response_mode?: string,
  resource_server_id?: string,
  claims?: (request: Request) => Record<string, unknown>
}

export default class Enforcer {
  /**
   * Construct a policy enforcer.
   *
   * @param config Config object.
   *
   * @constructor
   */
  constructor (public keycloak: Keycloak, public config: EnforcerConfig = {}) {
    if (!this.config.response_mode) {
      this.config.response_mode = 'permissions'
    }

    if (!this.config.resource_server_id) {
      this.config.resource_server_id = this.keycloak.getConfig().clientId
    }
  }

  enforce (permissions?: string | string[]) {
    const expectedPermissions = (typeof permissions === 'string') ? [permissions] : permissions

    return (request: Request, response: Response, next: NextFunction) => {
      if (!expectedPermissions || expectedPermissions.length === 0) {
        return next()
      }

      const authzRequest: AuthzRequest = {
        audience: this.config.resource_server_id
      }

      handlePermissions(expectedPermissions, (resource, scope) => {
        if (!authzRequest.permissions) {
          authzRequest.permissions = []
        }

        const permission: AuthzPermission = { id: resource }

        if (scope) {
          permission.scopes = [scope]
        }

        authzRequest.permissions.push(permission)
      })

      const accessToken = request.kauth?.grant?.access_token

      if (accessToken && handlePermissions(expectedPermissions, (resource, scope) => {
        if (!accessToken.hasPermission(resource, scope)) {
          return false
        }
      })) {
        return next()
      }

      if (this.config.claims) {
        const claims = this.config.claims(request)

        if (claims) {
          authzRequest.claim_token = Buffer.from(JSON.stringify(claims)).toString('base64')
          authzRequest.claim_token_format = 'urn:ietf:params:oauth:token-type:jwt'
        }
      }

      if (this.config.response_mode === 'permissions') {
        return this.keycloak.checkPermissions(authzRequest, this.config.response_mode, request, response).then((permissions) => {
          if (handlePermissions(expectedPermissions, (resource, scope) => {
            if (!permissions || permissions.length === 0) {
              return false
            }

            for (const permission of permissions) {
              if ((permission.rsid === resource || permission.rsname === resource) && scope) {
                if (permission.scopes && permission.scopes.length > 0) {
                  if (!permission.scopes.includes(scope)) {
                    return false
                  }
                  break
                }
                return false
              }
            }
          })) {
            request.permissions = permissions
            // eslint-disable-next-line promise/no-callback-in-promise
            return next()
          }

          return this.keycloak.accessDenied(request, response)
        }).catch(() => {
          return this.keycloak.accessDenied(request, response)
        })
      } else {
        return this.keycloak.checkPermissions(authzRequest, undefined, request, response).then((grant) => {
          if (handlePermissions(expectedPermissions, (resource, scope) => {
            if (!grant.access_token?.hasPermission(resource, scope)) {
              return false
            }
          })) {
            // eslint-disable-next-line promise/no-callback-in-promise
            return next()
          }

          return this.keycloak.accessDenied(request, response)
        }).catch(() => {
          return this.keycloak.accessDenied(request, response)
        })
      }
    }
  }
}
