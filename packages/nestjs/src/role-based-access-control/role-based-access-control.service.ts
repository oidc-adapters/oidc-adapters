import type { ExecutionContext } from '@nestjs/common'
import { Inject, Injectable } from '@nestjs/common'
import type { RolesProvider } from '@oidc-adapters/core'

export type RoleBasedAccessControlServiceOptions =
  RoleBasedAccessControlServiceOptionsContext
  | RoleBasedAccessControlServiceOptionsUser

export interface RoleBasedAccessControlServiceOptionsCommon {
  providerType: 'user' | 'context'
  provider: UserRolesProviderFactory | ContextRolesProviderFactory
}

export interface RoleBasedAccessControlServiceOptionsContext extends RoleBasedAccessControlServiceOptionsCommon {
  providerType: 'context'
  provider: ContextRolesProviderFactory
}

export interface RoleBasedAccessControlServiceOptionsUser extends RoleBasedAccessControlServiceOptionsCommon {
  providerType: 'user'
  provider: UserRolesProviderFactory
}

export type ContextRolesProviderFactory = (context: ExecutionContext) => RolesProvider
export type UserRolesProviderFactory = (user: Express.User) => RolesProvider

export const SERVICE_OPTIONS = Symbol('RoleBasedAccessControlServiceOptions')

@Injectable()
export class RoleBasedAccessControlService {
  constructor (@Inject(SERVICE_OPTIONS) private options: RoleBasedAccessControlServiceOptions) {
  }

  getRolesProvider (context: ExecutionContext): RolesProvider | undefined {
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
      const hasRole = await rolesProvider.hasRole(role)
      if (hasRole) {
        return true
      }
    }

    return false
  }
}
