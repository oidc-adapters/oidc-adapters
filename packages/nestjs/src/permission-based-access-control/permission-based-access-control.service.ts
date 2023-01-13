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

export const SERVICE_OPTIONS = Symbol('PermissionBasedAccessControlServiceOptions')

@Injectable()
export class PermissionBasedAccessControlService {
  constructor (@Inject(SERVICE_OPTIONS) private options: PermissionBasedAccessControlServiceOptions) {
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

  async hasAllPermissions (context: ExecutionContext, permissions: string | string[]): Promise<boolean> {
    const permissionsProvider = this.getPermissionsProvider(context)
    if (permissionsProvider === undefined) return false
    if (typeof permissions === 'string') {
      permissions = [permissions]
    }

    for (const permission of permissions) {
      const hasPermission = await permissionsProvider.hasPermission(permission)
      if (!hasPermission) {
        return false
      }
    }

    return true
  }

  async hasOnePermission (context: ExecutionContext, permissions: string | string[]): Promise<boolean> {
    const permissionsProvider = this.getPermissionsProvider(context)
    if (permissionsProvider === undefined) return false
    if (typeof permissions === 'string') {
      permissions = [permissions]
    }

    for (const permission of permissions) {
      const hasPermission = await permissionsProvider.hasPermission(permission)
      if (hasPermission) {
        return true
      }
    }

    return false
  }
}
