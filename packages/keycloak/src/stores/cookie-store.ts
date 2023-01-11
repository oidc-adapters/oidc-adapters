import type { Request, Response } from 'express'
import type { GrantJsonData } from '../middleware/auth-utils/grant.js'
import type { Store } from './index.js'
import type Grant from '../middleware/auth-utils/grant.js'

export const COOKIE_STORE_TOKEN_KEY = 'keycloak-token'

export default class CookieStore implements Store {
  get (request: Request): GrantJsonData | undefined {
    const value = request.cookies[COOKIE_STORE_TOKEN_KEY]
    if (value) {
      try {
        return JSON.parse(value) as GrantJsonData
      } catch {
        // ignore
      }
    }
  }

  wrap (grant: Grant) {
    grant.store = store(grant)
    grant.unstore = unstore
  }
}

function store (grant: Grant) {
  return (request: Request, response: Response) => {
    response.cookie(COOKIE_STORE_TOKEN_KEY, typeof grant.__raw === 'object' ? JSON.stringify(grant.__raw) : grant.__raw)
  }
}

function unstore (request: Request, response: Response) {
  response.clearCookie(COOKIE_STORE_TOKEN_KEY)
}
