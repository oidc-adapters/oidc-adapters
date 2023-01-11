import crypto from 'node:crypto'
import type { GrantData, GrantJsonData } from './grant.js'
import Grant from './grant.js'
import type { TokenAuthorizationPermission } from './token.js'
import Token from './token.js'
import Rotation from './rotation.js'
import type Config from './config.js'
import type { Request } from 'express'
import http from 'node:http'
import type { OidcStandardClaims } from 'oidc-client-ts'

export type AuthzRequestResponseMode = 'decision' | 'permissions' | undefined

export interface AuthzRequest {
  audience?: string
  response_mode?: AuthzRequestResponseMode
  claim_token?: string
  claim_token_format?: string
  permissions?: AuthzPermission[]
}

export interface AuthzPermission {
  id: string
  scopes?: string[]
}

export type CheckPermissionPermissionsResponse = TokenAuthorizationPermission[]

export interface CheckPermissionDecisionResponse {result: boolean}

export default class GrantManager {
  realmUrl: string
  clientId?: string
  secret?: string
  publicKey?: string
  public: boolean
  bearerOnly: boolean
  notBefore?: number
  rotation: Rotation
  verifyTokenAudience: boolean

  /**
   * Construct a grant manager.
   *
   * @param {Config} config Config object.
   *
   * @constructor
   */
  constructor (config: Config) {
    this.realmUrl = config.realmUrl
    this.clientId = config.clientId
    this.secret = config.secret
    this.publicKey = config.publicKey
    this.public = config.public
    this.bearerOnly = config.bearerOnly
    this.rotation = new Rotation(config)
    this.verifyTokenAudience = config.verifyTokenAudience
  }

  /**
   * Use the direct grant API to obtain a grant from Keycloak.
   *
   * The direct grant API must be enabled for the configured realm
   * for this method to work. This function ostensibly provides a
   * non-interactive, programatic way to login to a Keycloak realm.
   *
   * @param {String} username The username.
   * @param {String} password The cleartext password.
   */
  async obtainDirectly (username: string, password: string, scope = 'openid'): Promise<Grant> {
    const data = {
      client_id: this.clientId,
      username,
      password,
      grant_type: 'password',
      scope
    }

    const { url, options } = this.prepareFetch({ data })

    const response = await fetch(url, options)
    if (!response.ok) {
      const text = await response.text()
      throw new Error(`${response.status}:${http.STATUS_CODES[response.status]}:${text}`)
    }

    const json = await response.json() as GrantJsonData
    return this.createGrant(json)
  }

  /**
   * Obtain a grant from a previous interactive login which results in a code.
   *
   * This is typically used by servers which receive the code through a
   * redirect_uri when sending a user to Keycloak for an interactive login.
   *
   * An optional session ID and host may be provided if there is desire for
   * Keycloak to be aware of this information.  They may be used by Keycloak
   * when session invalidation is triggered from the Keycloak console itself
   * during its postbacks to `/k_logout` on the server.
   *
   * @param code The code from a successful login redirected from Keycloak.
   * @param sessionId Optional opaque session-id.
   * @param {String} sessionHost Optional session host for targetted Keycloak console post-backs.
   */
  async obtainFromCode (request: Request, code: string, sessionId: string, sessionHost?: string) {
    const data = {
      client_session_state: sessionId,
      client_session_host: sessionHost,
      code,
      grant_type: 'authorization_code',
      client_id: this.clientId,
      redirect_uri: request.session?.auth_redirect_uri
    }
    const { url, options } = this.prepareFetch({ data })

    const response = await fetch(url, options)
    if (!response.ok) {
      const text = response.text()
      throw new Error(`${response.status}:${http.STATUS_CODES[response.status]}:${text}`)
    }
    const json = await response.json() as GrantJsonData

    return this.createGrant(json)
  }

  async checkPermissions (authzRequest: AuthzRequest, responseMode: 'permissions', request: Request): Promise<CheckPermissionPermissionsResponse>
  async checkPermissions (authzRequest: AuthzRequest, responseMode: 'decision', request: Request): Promise<CheckPermissionDecisionResponse>
  async checkPermissions (authzRequest: AuthzRequest, responseMode: undefined, request: Request): Promise<Grant>
  async checkPermissions (authzRequest: AuthzRequest, responseMode: AuthzRequestResponseMode, request: Request): Promise<Grant | CheckPermissionPermissionsResponse | CheckPermissionDecisionResponse>
  async checkPermissions (authzRequest: AuthzRequest, responseMode: AuthzRequestResponseMode, request: Request): Promise<Grant | CheckPermissionPermissionsResponse | CheckPermissionDecisionResponse> {
    // eslint-disable-next-line unicorn/prevent-abbreviations
    const params: Record<string, undefined | string | string[]> = {
      grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket'
    }

    authzRequest = {
      ...authzRequest,
      response_mode: responseMode
    }

    if (authzRequest.audience) {
      params.audience = authzRequest.audience
    } else {
      params.audience = this.clientId
    }

    if (authzRequest.response_mode) {
      params.response_mode = authzRequest.response_mode
    }

    if (authzRequest.claim_token) {
      params.claim_token = authzRequest.claim_token
    }

    if (authzRequest.claim_token_format) {
      params.claim_token_format = authzRequest.claim_token_format
    }

    let permissions = authzRequest.permissions

    if (!permissions) {
      permissions = []
    }

    // eslint-disable-next-line unicorn/prevent-abbreviations
    let paramsPermissions: string[] | undefined
    for (const resource of permissions) {
      let permission = resource.id

      if (resource.scopes && resource.scopes.length > 0) {
        permission += '#'

        for (const scope of resource.scopes) {
          if (permission.indexOf('#') !== permission.length - 1) {
            permission += ','
          }
          permission += scope
        }
      }

      if (!paramsPermissions) {
        paramsPermissions = []
      }

      paramsPermissions.push(permission)
    }

    params.permission = paramsPermissions

    if (!this.public) {
      const authorizationHeader = request.get('Authorization')
      let bearerToken

      if (authorizationHeader && (authorizationHeader.indexOf('bearer ') === 0 || authorizationHeader.indexOf('Bearer ') === 0)) {
        bearerToken = authorizationHeader.slice(7)
      }

      if (!bearerToken) {
        if (request.kauth && request.kauth.grant && request.kauth.grant.access_token) {
          bearerToken = request.kauth.grant.access_token.token
        } else {
          throw new Error('No bearer in header')
        }
      }

      params.subject_token = bearerToken
    }

    const { url, options } = this.prepareFetch({ data: params })

    if (this.public && request.kauth && request.kauth.grant && request.kauth.grant.access_token) {
      options.headers.set('Authorization', `Bearer ${request.kauth.grant.access_token.token}`)
    }

    const response = await fetch(url, options)
    if (!response.ok) {
      const text = await response.text()
      throw new Error(`${response.status}:${http.STATUS_CODES[response.status]}:${text}`)
    }

    if (authzRequest.response_mode === 'decision') {
      return await response.json() as CheckPermissionDecisionResponse
    } else if (authzRequest.response_mode === 'permissions') {
      return await response.json() as CheckPermissionPermissionsResponse
    }

    return this.createGrant(await response.json() as GrantJsonData)
  }

  /**
   * Obtain a service account grant.
   * Client option 'Service Accounts Enabled' needs to be on.
   */
  async obtainFromClientCredentials (scope = 'openid') {
    const data = {
      grant_type: 'client_credentials',
      scope,
      client_id: this.clientId
    }

    const { url, options } = this.prepareFetch({ data })

    const response = await fetch(url, options)
    if (!response.ok) {
      const text = await response.text()
      throw new Error(`${response.status}:${http.STATUS_CODES[response.status]}:${text}`)
    }
    const json = await response.json() as GrantJsonData
    return this.createGrant(json)
  }

  /**
   * Ensure that a grant is *fresh*, refreshing if required & possible.
   *
   * If the access_token is not expired, the grant is left untouched.
   *
   * If the access_token is expired, and a refresh_token is available,
   * the grant is refreshed, in place (no new object is created),
   * and returned.
   *
   * If the access_token is expired and no refresh_token is available,
   * an error is provided.
   *
   * @param grant The grant object to ensure freshness of.
   */
  async ensureFreshness (grant: Grant): Promise<Grant> {
    if (!grant.isExpired()) {
      return grant
    }

    if (!grant.refresh_token) {
      throw new Error('Unable to refresh without a refresh token')
    }

    if (grant.refresh_token.isExpired()) {
      throw new Error('Unable to refresh with expired refresh token')
    }

    const data = {
      grant_type: 'refresh_token',
      refresh_token: grant.refresh_token.token,
      client_id: this.clientId
    }

    const { url, options } = this.prepareFetch({ data })

    const response = await fetch(url, options)
    if (!response.ok) {
      const text = await response.text()
      throw new Error(`${response.status}:${http.STATUS_CODES[response.status]}:${text}`)
    }

    const json = await response.json() as GrantJsonData
    return this.createGrant(json)
  }

  /**
   * Perform live validation of an `access_token` against the Keycloak server.
   *
   * @param {Token|String} token The token to validate.
   *
   * @return {boolean} `false` if the token is invalid, or the same token if valid.
   */
  async validateAccessToken (token: Token | string): Promise<Token | string | false> {
    const t = typeof token === 'object' ? token.token : token

    const data = {
      token: t,
      client_secret: this.secret,
      client_id: this.clientId
    }

    const { url, options } = this.prepareFetch({ path: '/protocol/openid-connect/token/introspect', data })

    const response = await fetch(url, options)
    if (!response.ok) {
      const text = await response.text()
      throw new Error(`${response.status}:${http.STATUS_CODES[response.status]}:${text}`)
    }

    const json = await response.json() as { active: unknown }
    if (!json.active) {
      return false
    }
    return token
  }

  async userInfo (token: string | Token): Promise<OidcStandardClaims> {
    const url = `${this.realmUrl}/protocol/openid-connect/userinfo`

    const t = (typeof token === 'object') ? token.token : token

    const response = await fetch(url, {
      method: 'get',
      headers: {
        Authorization: `Bearer ${t}`,
        Accept: 'application/json',
        'X-Client': 'keycloak-nodejs-connect'
      }
    })

    if (!response.ok) {
      const text = await response.text()
      throw new Error(`${response.status}:${http.STATUS_CODES[response.status]}:${text}`)
    }

    const json = await response.json() as { error: unknown }
    if (json.error) {
      throw new Error(JSON.stringify(json))
    }
    return json as OidcStandardClaims
  }

  isGrantRefreshable (grant: GrantData): boolean {
    return !this.bearerOnly && !!grant?.refresh_token
  }

  /**
   * Create a `Grant` object from a string of JSON data.
   *
   * This method creates the `Grant` object, including
   * the `access_token`, `refresh_token` and `id_token`
   * if available, and validates each for expiration and
   * against the known public-key of the server.
   *
   * @param {String} rawData The raw JSON string received from the Keycloak server or from a client.
   * @return {Promise} A promise reoslving a grant.
   */
  async createGrant (rawData: string | GrantJsonData): Promise<Grant> {
    const grantData = typeof rawData === 'string' ? JSON.parse(rawData) as GrantJsonData : rawData

    const grant = new Grant({
      access_token: (grantData.access_token ? new Token(grantData.access_token, this.clientId) : undefined),
      refresh_token: (grantData.refresh_token ? new Token(grantData.refresh_token) : undefined),
      id_token: (grantData.id_token ? new Token(grantData.id_token) : undefined),
      expires_in: grantData.expires_in,
      token_type: grantData.token_type,
      __raw: rawData
    })

    if (this.isGrantRefreshable(grant)) {
      const refreshedGrant = await this.ensureFreshness(grant)
      return await this.validateGrant(refreshedGrant)
    } else {
      return this.validateGrant(grant)
    }
  }

  /**
   * Validate the grant and all tokens contained therein.
   *
   * This method examines a grant (in place) and rejects
   * if any of the tokens are invalid. After this method
   * resolves, the passed grant is guaranteed to have
   * valid tokens.
   *
   * @param grant grant to validate.
   *
   * @return {Promise} That resolves to a validated grant or
   * rejects with an error if any of the tokens are invalid.
   */
  async validateGrant (grant: Grant): Promise<Grant> {
    const validateGrantToken = async (grant: Grant, tokenName: 'access_token' | 'id_token', expectedType: string) => {
      const grantToken = grant[tokenName]
      try {
        // check the access token
        const token = await this.validateToken(grantToken, expectedType)
        grant[tokenName] = token
      } catch (error) {
        throw new Error('Grant validation failed. Reason: ' + (error as Error).message)
      }
    }

    const promises = []

    promises.push(validateGrantToken(grant, 'access_token', 'Bearer'))
    if (!this.bearerOnly && grant.id_token) {
      promises.push(validateGrantToken(grant, 'id_token', 'ID'))
    }

    await Promise.all(promises)
    return grant
  }

  /**
   * Validate a token.
   *
   * This method accepts a token, and returns a promise
   *
   * If the token is valid the promise will be resolved with the token
   *
   * If the token is undefined or fails validation an applicable error is returned
   *
   * @return {Promise} That resolve a token
   */
  async validateToken (token?: Token, expectedType?: string) {
    if (!token) {
      throw new Error('invalid token (missing)')
    } else if (token.isExpired()) {
      throw new Error('invalid token (expired)')
    } else if (!token.signed) {
      throw new Error('invalid token (not signed)')
    } else if (token.content.typ !== expectedType) {
      throw new Error('invalid token (wrong type)')
    } else if (token.content.iat === undefined || (token.content.iat < (this.notBefore ?? 0))) {
      throw new Error('invalid token (stale token)')
    } else if (token.content.iss !== this.realmUrl) {
      throw new Error('invalid token (wrong ISS)')
    } else {
      const audienceData = token.content?.aud === undefined ? [] : (Array.isArray(token.content.aud) ? token.content.aud : [token.content.aud])
      if (expectedType === 'ID') {
        if (!this.clientId || !audienceData.includes(this.clientId)) {
          throw new Error('invalid token (wrong audience)')
        }
        if (token.content?.azp !== this.clientId) {
          throw new Error('invalid token (authorized party should match client id)')
        }
      } else if (this.verifyTokenAudience && (!this.clientId || !audienceData.includes(this.clientId))) {
        throw new Error('invalid token (wrong audience)')
      }
      const verify = crypto.createVerify('RSA-SHA256')
      // if public key has been supplied use it to validate token
      if (this.publicKey) {
        try {
          verify.update(token.signed)
        } catch {
          throw new Error('Misconfigured parameters while validating token. Check your keycloak.json file!')
        }

        if (!token.signature || !verify.verify(this.publicKey, token.signature)) {
          throw new Error('invalid token (signature)')
        } else {
          return token
        }
      } else {
        // retrieve public KEY and use it to validate token
        if (!token.header?.kid) {
          throw new Error('invalid token (missing kid)')
        }
        let key: string | undefined
        try {
          key = await this.rotation.getJWK(token.header.kid)
        } catch (error: unknown) {
          throw new Error(`failed to load public key to verify token. Reason: ${(error as Error).message}`)
        }
        verify.update(token.signed)
        if (!key || !token.signature || !verify.verify(key, token.signature)) {
          throw new Error('invalid token (public key signature)')
        } else {
          return token
        }
      }
    }
  }

  private prepareFetch (input?: { path?: string, data?: Record<string, string[] | string | undefined> }): { url: string, options: RequestInit & { headers: Headers } } {
    const headers = new Headers()

    headers.set('Content-Type', 'application/x-www-form-urlencoded')
    headers.set('X-Client', 'keycloak-nodejs-connect')
    if (!this.public) {
      headers.set('Authorization', 'Basic ' + Buffer.from(`${this.clientId}:${this.secret}`).toString('base64'))
    }

    const body: string[][] = []
    if (input?.data) {
      for (const [key, value] of Object.entries(input.data)) {
        if (value !== undefined && value !== null) {
          if (Array.isArray(value)) {
            for (const item of value) {
              body.push([key, item])
            }
          } else {
            body.push([key, value])
          }
        }
      }
    }

    const options: RequestInit & { headers: Headers } = {
      method: 'post',
      headers,
      body: new URLSearchParams(body)
    }

    const path = input?.path ?? '/protocol/openid-connect/token'

    return { url: `${this.realmUrl}${path}`, options }
  }
}
