import type { ExecutionContext } from '@nestjs/common'
import { Inject, Injectable } from '@nestjs/common'
import type { RolesProvider } from '@oidc-adapters/core'

export type RoleBasedAccessControlServiceOptions =
  RoleBasedAccessControlServiceOptionsContext
  | RoleBasedAccessControlServiceOptionsUser

export interface RoleBasedAccessControlServiceOptionsCommon {
  rolesProviderType: 'user' | 'context'
  rolesProvider: UserRolesProviderFactory | ContextRolesProviderFactory
}

export interface RoleBasedAccessControlServiceOptionsContext extends RoleBasedAccessControlServiceOptionsCommon {
  rolesProviderType: 'context'
  rolesProvider: ContextRolesProviderFactory
}

export interface RoleBasedAccessControlServiceOptionsUser extends RoleBasedAccessControlServiceOptionsCommon {
  rolesProviderType: 'user'
  rolesProvider: UserRolesProviderFactory
}

export type ContextRolesProviderFactory = (context: ExecutionContext) => RolesProvider
export type UserRolesProviderFactory = (user: Express.User) => RolesProvider

export const SERVICE_OPTIONS = Symbol('RoleBasedAccessControlServiceOptions')

@Injectable()
export class RoleBasedAccessControlService {
  constructor (@Inject(SERVICE_OPTIONS) private options: RoleBasedAccessControlServiceOptions) {
  }

  getRolesProvider (context: ExecutionContext): RolesProvider | undefined {
    if (this.options.rolesProviderType === 'context') {
      return this.options.rolesProvider(context)
    } else if (this.options.rolesProviderType === 'user' && context.getType() === 'http') {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const request = context.switchToHttp().getRequest()
      const user = (request as Express.Request).user
      if (user !== undefined) {
        return this.options.rolesProvider(user)
      }
    } // TODO: add support for GraphQL context
  }

  async hasAllRoles (context: ExecutionContext, roles: string | string[]): Promise<boolean> {
    const rolesProvider = this.getRolesProvider(context)
    if (rolesProvider === undefined) return false
    if (typeof roles === 'string') {
      roles = [roles]
    }

    for (const role of roles) {
      // eslint-disable-next-line @typescript-eslint/await-thenable
      const hasRole = await rolesProvider.hasRole(role)
      if (!hasRole) {
        return false
      }
    }

    return true
  }

  async hasOneRole (context: ExecutionContext, roles: string | string[]): Promise<boolean> {
    const rolesProvider = this.getRolesProvider(context)
    if (rolesProvider === undefined) return false
    if (typeof roles === 'string') {
      roles = [roles]
    }

    for (const role of roles) {
      // eslint-disable-next-line @typescript-eslint/await-thenable
      const hasRole = await rolesProvider.hasRole(role)
      if (hasRole) {
        return true
      }
    }

    return false
  }
}
