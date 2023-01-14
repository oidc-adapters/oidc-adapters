import type { CheckPermissionPermissionsResponse } from './middleware/auth-utils/grant-manager.js'
import type Grant from './middleware/auth-utils/grant.js'
import type { COOKIE_STORE_TOKEN_KEY } from './stores/cookie-store.js'
import type { SESSION_STORE_TOKEN_KEY } from './stores/session-store.js'

export interface KCookies {
  [COOKIE_STORE_TOKEN_KEY]?: string
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface KAuth {
      grant?: Grant
    }

    interface Request {
      kauth?: KAuth
      permissions?: CheckPermissionPermissionsResponse
      cookies?: KCookies
    }
  }
}

declare module 'express' {
  interface Request {
    cookies: KCookies
  }
}

declare module 'express-session' {
  interface SessionData {
    [SESSION_STORE_TOKEN_KEY]?: string
    'auth_redirect_uri'?: string
    'auth_is_check_sso_complete'?: boolean
  }
}
