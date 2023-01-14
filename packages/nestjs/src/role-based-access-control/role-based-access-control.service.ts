import type { ExecutionContext } from '@nestjs/common'
import { Inject, Injectable } from '@nestjs/common'
import type { RolesProvider } from '@oidc-adapters/core'
import { userFromContext } from '../common/context.utils.js'

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

export const ROLE_BASED_ACCESS_CONTROL_SERVICE_OPTIONS = Symbol('RoleBasedAccessControlServiceOptions')

@Injectable()
export class RoleBasedAccessControlService {
  constructor (@Inject(ROLE_BASED_ACCESS_CONTROL_SERVICE_OPTIONS) private options: RoleBasedAccessControlServiceOptions) {
  }

  private getRolesProvider (context: ExecutionContext): RolesProvider | undefined {
    if (this.options.providerType === 'context') {
      return this.options.provider(context)
    } else if (this.options.providerType === 'user') {
      const user = userFromContext(context)
      if (user !== undefined) {
        return this.options.provider(user)
      }
    }
  }

  async hasAllRoles (context: ExecutionContext, roles: string | Iterable<string>): Promise<boolean> {
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

  async hasOneRole (context: ExecutionContext, roles: string | Iterable<string>): Promise<boolean> {
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
