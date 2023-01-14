import type { ExecutionContext } from '@nestjs/common'
import { Inject, Injectable } from '@nestjs/common'
import type { PermissionsProvider } from '@oidc-adapters/core'

export type PermissionBasedAccessControlServiceOptions =
  PermissionBasedAccessControlServiceOptionsContext
  | PermissionBasedAccessControlServiceOptionsUser

export interface PermissionBasedAccessControlServiceOptionsCommon {
  providerType: 'user' | 'context'
  provider: UserPermissionsProviderFactory | ContextPermissionsProviderFactory
}

export interface PermissionBasedAccessControlServiceOptionsContext extends PermissionBasedAccessControlServiceOptionsCommon {
  providerType: 'context'
  provider: ContextPermissionsProviderFactory
}

export interface PermissionBasedAccessControlServiceOptionsUser extends PermissionBasedAccessControlServiceOptionsCommon {
  providerType: 'user'
  provider: UserPermissionsProviderFactory
}

export type ContextPermissionsProviderFactory = (context: ExecutionContext) => PermissionsProvider
export type UserPermissionsProviderFactory = (user: Express.User) => PermissionsProvider

export const PERMISSION_BASED_ACCESS_CONTROL_SERVICE_OPTIONS = Symbol('PermissionBasedAccessControlServiceOptions')

export interface PermissionScopesSpec {
  resource?: string,
  scopes: string | string[]
}

export type PermissionsSpec = string | PermissionScopesSpec | (string | PermissionScopesSpec)[]

@Injectable()
export class PermissionBasedAccessControlService {
  constructor (@Inject(PERMISSION_BASED_ACCESS_CONTROL_SERVICE_OPTIONS) private options: PermissionBasedAccessControlServiceOptions) {
  }

  getPermissionsProvider (context: ExecutionContext): PermissionsProvider | undefined {
    if (this.options.providerType === 'context') {
      return this.options.provider(context)
    } else if (this.options.providerType === 'user' && context.getType() === 'http') {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const request = context.switchToHttp().getRequest()
      const user = (request as Express.Request).user
      if (user !== undefined) {
        return this.options.provider(user)
      }
    } // TODO: add support for GraphQL context
  }

  async hasAllPermissions (context: ExecutionContext, permissions: PermissionsSpec): Promise<boolean> {
    const permissionsProvider = this.getPermissionsProvider(context)
    if (permissionsProvider === undefined) return false
    if (!Array.isArray(permissions)) {
      permissions = [permissions]
    }

    for (const permission of permissions) {
      if (typeof permission === 'string') {
        const hasPermission = await permissionsProvider.hasPermission(permission)
        if (!hasPermission) {
          return false
        }
      } else if (permission.scopes.length === 0) {
        const hasPermission = await permissionsProvider.hasPermission(permission.resource ?? '')
        if (!hasPermission) {
          return false
        }
      } else {
        for (const scope of permission.scopes) {
          const hasPermission = await permissionsProvider.hasResourcePermission(permission.resource ?? '', scope)
          if (!hasPermission) {
            return false
          }
        }
      }
    }

    return true
  }

  async hasOnePermission (context: ExecutionContext, permissions: PermissionsSpec): Promise<boolean> {
    const permissionsProvider = this.getPermissionsProvider(context)
    if (permissionsProvider === undefined) return false
    if (!Array.isArray(permissions)) {
      permissions = [permissions]
    }

    for (const permission of permissions) {
      if (typeof permission === 'string') {
        const hasPermission = await permissionsProvider.hasPermission(permission)
        if (hasPermission) {
          return true
        }
      } else if (permission.scopes.length === 0) {
        const hasPermission = await permissionsProvider.hasPermission(permission.resource ?? '')
        if (hasPermission) {
          return true
        }
      } else {
        for (const scope of permission.scopes) {
          const hasPermission = await permissionsProvider.hasResourcePermission(permission.resource ?? '', scope)
          if (hasPermission) {
            return true
          }
        }
      }
    }

    return false
  }
}
