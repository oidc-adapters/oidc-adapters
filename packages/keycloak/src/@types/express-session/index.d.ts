import { SESSION_STORE_TOKEN_KEY } from '../../stores/session-store.js'

// This is required for this to augment the existing module.
export {}

module 'express-session' {
  interface SessionData {
    [SESSION_STORE_TOKEN_KEY]?: string
    'auth_redirect_uri'?: string
    'auth_is_check_sso_complete'?: boolean
  }
}
