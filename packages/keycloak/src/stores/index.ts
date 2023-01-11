import type { Request } from 'express'
import type { GrantJsonData } from '../middleware/auth-utils/grant.js'
import type Grant from '../middleware/auth-utils/grant.js'

export interface Store {
  get (request: Request): GrantJsonData | undefined

  clear? (sessionId: string): void | Promise<void>

  wrap? (grant: Grant): void
}
