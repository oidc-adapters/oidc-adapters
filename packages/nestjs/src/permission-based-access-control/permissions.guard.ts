import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Inject, Injectable, mixin } from '@nestjs/common'
import type { Type, AuthGuard, IAuthGuard } from '@nestjs/passport'
import type { PermissionsSpec } from './permission-based-access-control.service.js'
import { PermissionBasedAccessControlService } from './permission-based-access-control.service.js'

export interface PermissionsGuardOptions {
  mode?: 'one' | 'all',
  authGuard?: Type<IAuthGuard> | Parameters<typeof AuthGuard>[0]
}

export const PERMISSIONS_GUARD_OPTIONS = Symbol('PermissionsGuardOptions')

export function PermissionsGuard (permissions: PermissionsSpec, options?: PermissionsGuardOptions): Type<CanActivate> {
  @Injectable()
  class PermissionsGuardMixin implements CanActivate {
    constructor (@Inject(PermissionBasedAccessControlService) private service: PermissionBasedAccessControlService) {
    }

    canActivate (context: ExecutionContext): boolean | Promise<boolean> {
      if (options?.mode === 'all') {
        return this.service.hasAllPermissions(context, permissions)
      }
      return this.service.hasOnePermission(context, permissions)
    }
  }

  return mixin(PermissionsGuardMixin)
}
