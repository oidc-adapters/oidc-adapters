import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Inject, Injectable, mixin } from '@nestjs/common'
import type { Type } from '@nestjs/passport'
import { RoleBasedAccessControlService } from './role-based-access-control.service.js'

export interface RolesGuardOptions {
  mode: 'one' | 'all'
}

export function RolesGuard (roles: string | string[], options?: RolesGuardOptions): Type<CanActivate> {
  @Injectable()
  class RolesGuardMixin implements CanActivate {
    constructor (@Inject(RoleBasedAccessControlService) private service: RoleBasedAccessControlService) {
    }

    canActivate (context: ExecutionContext): boolean | Promise<boolean> {
      if (options?.mode === 'all') {
        return this.service.hasAllRoles(context, roles)
      }
      return this.service.hasOneRole(context, roles)
    }
  }

  return mixin(RolesGuardMixin)
}
