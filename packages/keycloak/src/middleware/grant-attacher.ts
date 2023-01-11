import type Keycloak from '../keycloak.js'
import type { Request, Response, NextFunction } from 'express'

export default function (keycloak: Keycloak) {
  return async function grantAttacher (request: Request, response: Response, next: NextFunction) {
    try {
      const grant = await keycloak.getGrant(request, response)
      if (!request.kauth) {
        request.kauth = {}
      }
      request.kauth.grant = grant
      next()
    } catch {
      next()
    }
  }
}
