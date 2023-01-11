import type { Request } from 'express'
import type { GrantJsonData } from '../middleware/auth-utils/grant.js'
import type Grant from '../middleware/auth-utils/grant.js'
import type { Store } from './index.js'
import type { SessionData, Store as ExpressSessionStore } from 'express-session'

export const SESSION_STORE_TOKEN_KEY = 'keycloak-token'

export default class SessionStore implements Store {
  constructor (private store: ExpressSessionStore) {
  }

  get (request: Request): GrantJsonData | undefined {
    return request.session[SESSION_STORE_TOKEN_KEY] as GrantJsonData | undefined
  }

  async clear (sessionId: string) {
    const session = await new Promise<SessionData | null | undefined>((resolve, reject) => {
      this.store.get(sessionId, (error, session) => {
        if (error) {
          reject(error)
        } else {
          resolve(session)
        }
      })
    })
    if (session) {
      delete session[SESSION_STORE_TOKEN_KEY]
      this.store.set(sessionId, session)
    }
  }

  wrap (grant: Grant) {
    if (grant) {
      grant.store = store(grant)
      grant.unstore = unstore
    }
  }
}

function store (grant: Grant) {
  return (request: Request): void => {
    request.session[SESSION_STORE_TOKEN_KEY] = typeof grant.__raw === 'object' ? JSON.stringify(grant.__raw) : grant.__raw
  }
}

function unstore (request: Request): void {
  delete request.session[SESSION_STORE_TOKEN_KEY]
}
