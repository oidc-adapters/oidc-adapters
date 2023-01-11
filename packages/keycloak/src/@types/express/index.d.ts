import { CheckPermissionPermissionsResponse } from '../../middleware/auth-utils/grant-manager.js'
import GrantData from '../../middleware/auth-utils/grant.js'
import { COOKIE_STORE_TOKEN_KEY } from '../../stores/cookie-store.js'

// This is required for this to augment the existing module.
export {}

declare global {
  namespace Express {
    interface KAuth {
      grant?: GrantData
    }

    interface Request {
      kauth?: KAuth
      permissions?: CheckPermissionPermissionsResponse
      cookies?: KCookies
    }
  }
}

declare module 'express' {
  interface KCookies {
    [COOKIE_STORE_TOKEN_KEY]?: string
  }

  interface Request {
    cookies: KCookies
  }
}
