import type Token from './token.js'
import type { Request, Response } from 'express'

export interface GrantJsonData {
  access_token?: string
  refresh_token?: string
  id_token?: string
  token_type?: string
  expires_in?: number
  error?: unknown
}

export interface GrantData {
  __raw?: string | GrantJsonData
  access_token?: Token
  refresh_token?: Token
  id_token?: Token
  token_type?: string
  expires_in?: number
}

export default class Grant implements GrantData {
  __raw?: string | GrantJsonData
  access_token?: Token
  refresh_token?: Token
  id_token?: Token
  token_type?: string
  expires_in?: number

  store?: (request: Request, response: Response) => void
  unstore?: (request: Request, response: Response) => void

  /**
   * Construct a new grant.
   *
   * The passed in argument may be another `Grant`, or any object with
   * at least `access_token`, and optionally `refresh_token` and `id_token`,
   * `token_type`, and `expires_in`.  Each token should be an instance of
   * `Token` if present.
   *
   * If the passed in object contains a field named `__raw` that is also stashed
   * away as the verbatim raw `String` data of the grant.
   *
   * @param grant The `Grant` to copy, or a simple `Object` with similar fields.
   */
  constructor (grant: GrantData) {
    this.update(grant)
  }

  /**
   * Update this grant in-place given data in another grant.
   *
   * This is used to avoid making client perform extra-bookkeeping
   * to maintain the up-to-date/refreshed grant-set.
   */
  update (grant: GrantData) {
    // intentional naming with under_scores instead of
    // CamelCase to match both Keycloak's grant JSON
    // and to allow new Grant(new Grant(kc)) copy-ctor

    this.access_token = grant.access_token
    this.refresh_token = grant.refresh_token
    this.id_token = grant.id_token

    this.token_type = grant.token_type
    this.expires_in = grant.expires_in
    this.__raw = grant.__raw
  }

  /**
   * Returns the raw String of the grant, if available.
   *
   * If the raw string is unavailable (due to programatic construction)
   * then `undefined` is returned.
   */
  toString (): string | undefined {
    return typeof this.__raw === 'string' ? this.__raw : JSON.stringify(this.__raw)
  }

  /**
   * Determine if this grant is expired/out-of-date.
   *
   * Determination is made based upon the expiration status of the `access_token`.
   *
   * An expired grant *may* be possible to refresh, if a valid
   * `refresh_token` is available.
   *
   * @return {boolean} `true` if expired, otherwise `false`.
   */
  isExpired (): boolean {
    if (!this.access_token) {
      return true
    }
    return this.access_token.isExpired()
  }
}
