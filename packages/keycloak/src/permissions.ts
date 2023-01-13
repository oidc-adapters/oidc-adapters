import type { DirectGrantErrorResponse, DirectGrantResponse, PermissionsProvider } from '@oidc-adapters/core'
import { createMetadataService, DirectGrantResponseError } from '@oidc-adapters/core'
import type { IdTokenClaims } from 'oidc-client-ts'
import jwtDecode from 'jwt-decode'

export interface KeycloakPermissionClaim {
  rsname: string
  rsid: string
  scopes: string[]
}

export interface KeycloakAuthorizationPermissionsClaim {
  permissions: KeycloakPermissionClaim[]
}

export interface KeycloakAuthorizationDecisionResult {
  result: boolean
}

export interface KeycloakUmaTicketTokenClaims extends Partial<IdTokenClaims> {
  authorization?: KeycloakAuthorizationPermissionsClaim
}

export interface FetchUmaTicketOptions {
  token?: IdTokenClaims | string
  encodedToken?: string
  audience?: string
  tokenEndpoint?: string
  authority?: string
  permission?: string | string[]
  responseMode?: 'decision' | 'permissions'
}

export class KeycloakPermissionsProviderError extends Error {

}

function umaTicketEffectiveOptions (options?: FetchUmaTicketOptions) {
  const effectiveOptions = {
    ...options
  }

  let token: IdTokenClaims | undefined = typeof effectiveOptions.token !== 'string' ? effectiveOptions.token : undefined
  if (typeof effectiveOptions?.token === 'string' && !effectiveOptions.encodedToken) {
    effectiveOptions.encodedToken = effectiveOptions.token
    token = jwtDecode(effectiveOptions.token)
  }

  if (effectiveOptions?.encodedToken && !token) {
    token = jwtDecode(effectiveOptions.encodedToken)
  }

  return { ...effectiveOptions, token }
}

async function fetchUmaTicket (options?: FetchUmaTicketOptions) {
  const effectiveOptions = umaTicketEffectiveOptions(options)

  const data = new URLSearchParams()
  data.append('grant_type', 'urn:ietf:params:oauth:grant-type:uma-ticket')
  const audience = effectiveOptions?.audience ?? effectiveOptions.token?.azp
  if (audience) {
    data.append('audience', audience)
  }
  if (options?.responseMode !== undefined) {
    data.append('response_mode', options.responseMode)
  }
  if (options?.permission !== undefined) {
    const permissions = Array.isArray(options.permission) ? options.permission : [options.permission]
    for (const permission of permissions) {
      data.append('permission', permission)
    }
  }

  const headers = new Headers()

  headers.set('Content-Type', 'application/x-www-form-urlencoded')
  if (effectiveOptions?.encodedToken) {
    headers.set('Authorization', `Bearer ${effectiveOptions.encodedToken}`)
  }

  let tokenEndpoint = effectiveOptions?.tokenEndpoint
  if (tokenEndpoint === undefined) {
    const authority = effectiveOptions?.authority ?? effectiveOptions.token?.iss
    const metadataService = createMetadataService({ authority })
    tokenEndpoint = await metadataService.getTokenEndpoint()
  }
  if (!tokenEndpoint) {
    throw new KeycloakPermissionsProviderError('Token endpoint is not defined')
  }

  const umaTicketResponse = await fetch(tokenEndpoint, { method: 'post', headers, body: data })
  if (!umaTicketResponse.ok) {
    const json = await umaTicketResponse.json() as DirectGrantErrorResponse
    throw new DirectGrantResponseError(json)
  }
  return umaTicketResponse
}

export async function fetchUmaTicketPermissionsToken (options?: Omit<FetchUmaTicketOptions, 'responseMode'>): Promise<KeycloakUmaTicketTokenClaims> {
  const umaTicketResponse = await fetchUmaTicket({ ...options, responseMode: undefined })

  const json = await umaTicketResponse.json() as DirectGrantResponse
  const umaTicket = jwtDecode(json.access_token)
  return umaTicket as KeycloakUmaTicketTokenClaims
}

export async function fetchUmaTicketDecision (options?: Omit<FetchUmaTicketOptions, 'responseMode'>): Promise<KeycloakAuthorizationDecisionResult> {
  const umaTicketResponse = await fetchUmaTicket({ ...options, responseMode: 'decision' })

  return await umaTicketResponse.json() as KeycloakAuthorizationDecisionResult
}

export class KeycloakPermissionsProvider implements PermissionsProvider {
  private umaTicketProvider: PermissionsProvider | undefined
  private effectiveOptions: ReturnType<typeof umaTicketEffectiveOptions>

  constructor (options?: FetchUmaTicketOptions) {
    this.effectiveOptions = umaTicketEffectiveOptions(options)
  }

  private async getUmaTicketPermissionsProvider (): Promise<PermissionsProvider> {
    if (this.umaTicketProvider !== undefined) return this.umaTicketProvider
    if ((this.effectiveOptions.token as KeycloakUmaTicketTokenClaims).authorization !== undefined) {
      this.umaTicketProvider = new KeycloakUmaTicketPermissionsProvider(this.effectiveOptions.token as KeycloakUmaTicketTokenClaims)
      return this.umaTicketProvider
    }
    const umaTicketToken = await fetchUmaTicketPermissionsToken(this.effectiveOptions)
    this.umaTicketProvider = new KeycloakUmaTicketPermissionsProvider(umaTicketToken)
    return this.umaTicketProvider
  }

  private buildPermissionString (resource: string, scope: string) {
    return `${resource}#${scope}`
  }

  async evaluatePermission (permission: string) {
    try {
      const umaTicketDecision = await fetchUmaTicketDecision({
        ...this.effectiveOptions,
        permission
      })
      return !!umaTicketDecision?.result
    } catch (error: unknown) {
      const grantError = error as DirectGrantResponseError
      if ((grantError.json?.error as string) === 'access_denied' && grantError.json?.error_description === 'not_authorized') {
        return false
      }
      if ((grantError.json?.error as string) === 'invalid_resource') {
        return false
      }
      if ((grantError.json?.error as string) === 'invalid_scope') {
        return false
      }
      throw error
    }
  }

  async hasPermission (permission: string): Promise<boolean> {
    if (this.effectiveOptions.responseMode === 'decision') {
      return this.evaluatePermission(permission)
    }

    const umaTicketProvider = await this.getUmaTicketPermissionsProvider()
    return umaTicketProvider.hasPermission(permission)
  }

  async hasResourcePermission (resource: string, permission: string): Promise<boolean> {
    if (this.effectiveOptions.responseMode === 'decision') {
      return this.evaluatePermission(this.buildPermissionString(resource, permission))
    }

    const umaTicketProvider = await this.getUmaTicketPermissionsProvider()
    return umaTicketProvider.hasResourcePermission(resource, permission)
  }

  async getPermissions (): Promise<string[]> {
    const umaTicketProvider = await this.getUmaTicketPermissionsProvider()
    return umaTicketProvider.getPermissions()
  }

  async getResourcePermissions (resource: string): Promise<string[]> {
    const umaTicketProvider = await this.getUmaTicketPermissionsProvider()
    return umaTicketProvider.getResourcePermissions(resource)
  }
}

export class KeycloakUmaTicketPermissionsProvider implements PermissionsProvider {
  private permissions: Set<string> = new Set()
  private resourcePermissions: Map<string, Set<string>> = new Map()

  constructor (private umaTicketToken: KeycloakUmaTicketTokenClaims) {
    if (this.umaTicketToken.authorization?.permissions !== undefined) {
      for (const permission of this.umaTicketToken.authorization.permissions) {
        const resourceString = this.buildResourceString(permission)
        const currentResourcePermissions: Set<string> = new Set()
        if (permission.scopes) {
          for (const scope of permission.scopes) {
            const permissionString = this.buildPermissionString(resourceString, scope)
            this.permissions.add(permissionString)
            currentResourcePermissions.add(scope)
          }
        }
        this.resourcePermissions.set(resourceString, currentResourcePermissions)
      }
    }
  }

  private buildResourceString (permission: KeycloakPermissionClaim) {
    return permission.rsname ?? permission.rsid
  }

  private buildPermissionString (resource: string, scope: string) {
    return `${resource}#${scope}`
  }

  hasPermission (permission: string): boolean {
    return this.permissions.has(permission) || this.resourcePermissions.has(permission)
  }

  hasResourcePermission (resource: string, permission: string): boolean {
    const currentResourcePermissions = this.resourcePermissions.get(resource)
    return currentResourcePermissions ? currentResourcePermissions.has(permission) : false
  }

  getPermissions (): string[] {
    return [...this.permissions]
  }

  getResourcePermissions (resource: string): string[] | Promise<string[]> {
    const currentResourcePermissions = this.resourcePermissions.get(resource)
    return currentResourcePermissions ? [...currentResourcePermissions] : []
  }
}
