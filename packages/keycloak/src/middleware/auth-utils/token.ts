import type { IdTokenClaims, JwtClaims } from 'oidc-client-ts'

export interface TokenHeader {
  [key: string]: string
}

export interface TokenContent extends JwtClaims, Partial<IdTokenClaims> {
  typ: string,
  notBefore: number,
  action?: string
  adapterSessionIds: string
  resource_access?: Record<string, TokenResourceAccessValue>
  realm_access?: TokenResourceAccessValue
  authorization?: TokenAuthorizationValue
}

export interface TokenResourceAccessValue {
  roles: string[]
}

export interface TokenAuthorizationValue {
  permissions: TokenAuthorizationPermission[]
}

export interface TokenAuthorizationPermission {
  rsid?: string,
  rsname?: string,
  scopes?: string[]
}

export default class Token {
  public header!: TokenHeader
  public content!: TokenContent
  public signature!: Buffer
  public signed!: string

  /**
   * Construct a token.
   *
   * Based on a JSON Web Token string, construct a token object. Optionally
   * if a `clientId` is provided, the token may be tested for roles with
   * `hasRole()`.
   *
   * @param token The JSON Web Token formatted token string.
   * @param clientId Optional clientId if this is an `access_token`.
   */
  constructor (public token: string, public clientId?: string) {
    try {
      const parts = token.split('.')
      this.header = JSON.parse(Buffer.from(parts[0], 'base64').toString()) as typeof this.header
      this.content = JSON.parse(Buffer.from(parts[1], 'base64').toString()) as typeof this.content
      this.signature = Buffer.from(parts[2], 'base64')
      this.signed = parts[0] + '.' + parts[1]
    } catch {
      // Do nothing
    }
  }

  /**
   * Determine if this token is expired.
   *
   * @return `true` if it is expired, otherwise `false`.
   */
  isExpired () {
    if (this.content?.exp === undefined) return false
    return ((this.content.exp * 1000) < Date.now())
  }

  /**
   * Determine if this token has an associated role.
   *
   * This method is only functional if the token is constructed
   * with a `clientId` parameter.
   *
   * The parameter matches a role specification using the following rules:
   *
   * - If the name contains no colons, then the name is taken as the entire
   *   name of a role within the current application, as specified via
   *   `clientId`.
   * - If the name starts with the literal `realm:`, the subsequent portion
   *   is taken as the name of a _realm-level_ role.
   * - Otherwise, the name is split at the colon, with the first portion being
   *   taken as the name of an arbitrary application, and the subsequent portion
   *   as the name of a role with that app.
   *
   * @param {String} name The role name specifier.
   *
   * @return {boolean} `true` if this token has the specified role, otherwise `false`.
   */
  hasRole (name: string) {
    if (!this.clientId) {
      return false
    }

    const parts = name.split(':')
    if (parts.length === 1) {
      return this.hasApplicationRole(this.clientId, parts[0])
    }

    if (parts[0] === 'realm') {
      return this.hasRealmRole(parts[1])
    }

    return this.hasApplicationRole(parts[0], parts[1])
  }

  /**
   * Determine if this token has an associated specific application role.
   *
   * Even if `clientId` is not set, this method may be used to explicitly test
   * roles for any given application.
   *
   * @param {String} appName The identifier of the application to test.
   * @param {String} roleName The name of the role within that application to test.
   *
   * @return {boolean} `true` if this token has the specified role, otherwise `false`.
   */
  hasApplicationRole (appName: string, roleName: string) {
    if (!this.content?.resource_access) {
      return false
    }

    const appRoles = this.content.resource_access[appName]

    if (!appRoles) {
      return false
    }

    return appRoles.roles.includes(roleName)
  }

  /**
   * Determine if this token has an associated specific realm-level role.
   *
   * Even if `clientId` is not set, this method may be used to explicitly test
   * roles for the realm.
   *
   * @param roleName The name of the role within that application to test.
   *
   * @return `true` if this token has the specified role, otherwise `false`.
   */
  hasRealmRole (roleName: string) {
    // Make sure we have these properties before we check for a certain realm level role!
    // Without this we attempt to access an undefined property on token
    // for a user with no realm level roles.
    if (!this.content?.realm_access?.roles) {
      return false
    }

    return this.content.realm_access.roles.includes(roleName)
  }

  /**
   * Determine if this token has an associated role.
   *
   * This method is only functional if the token is constructed
   * with a `clientId` parameter.
   *
   * The parameter matches a role specification using the following rules:
   *
   * - If the name contains no colons, then the name is taken as the entire
   *   name of a role within the current application, as specified via
   *   `clientId`.
   * - If the name starts with the literal `realm:`, the subsequent portion
   *   is taken as the name of a _realm-level_ role.
   * - Otherwise, the name is split at the colon, with the first portion being
   *   taken as the name of an arbitrary application, and the subsequent portion
   *   as the name of a role with that app.
   *
   * @param resource The resource name.
   * @param scope The scope name.
   *
   * @return `true` if this token has the specified role, otherwise `false`.
   */
  hasPermission (resource: string, scope?: string) {
    const permissions = this.content?.authorization?.permissions

    if (!permissions) {
      return false
    }

    for (const permission of permissions) {
      if (permission.rsid === resource || permission.rsname === resource) {
        if (scope && permission.scopes && permission.scopes.length > 0 && !permission.scopes.includes(scope)) {
          return false
        }

        return true
      }
    }

    return false
  }
}
