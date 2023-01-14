import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Inject, Injectable, mixin, Optional } from '@nestjs/common'
import type { IAuthGuard, Type, AuthGuard } from '@nestjs/passport'
import { RoleBasedAccessControlService } from './role-based-access-control.service.js'
import { ModuleRef } from '@nestjs/core'

export interface RolesGuardOptions {
  mode?: 'one' | 'all',
  authGuard?: Type<IAuthGuard> | Parameters<typeof AuthGuard>[0]
}

export const ROLES_GUARD_OPTIONS = Symbol('RolesGuardOptions')

export function RolesGuard (roles: string | Iterable<string>, options?: RolesGuardOptions): Type<CanActivate> {
  @Injectable()
  class RolesGuardMixin implements CanActivate {
    private effectiveOptions: RolesGuardOptions

    constructor (
      @Inject(RoleBasedAccessControlService) private service: RoleBasedAccessControlService,
      @Optional() @Inject(ROLES_GUARD_OPTIONS) private defaultOptions: RolesGuardOptions,
      // eslint-disable-next-line unicorn/prevent-abbreviations
      @Inject(ModuleRef) private moduleRef: ModuleRef) {
      this.effectiveOptions = { ...defaultOptions, ...options }
    }

    async canActivate (context: ExecutionContext) {
      if (this.effectiveOptions?.mode === 'all') {
        return this.service.hasAllRoles(context, roles)
      }
      return this.service.hasOneRole(context, roles)
    }
  }

  return mixin(RolesGuardMixin)
}
