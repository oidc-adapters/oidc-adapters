import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Inject, Injectable, mixin } from '@nestjs/common'
import type { Type } from '@nestjs/passport'
import { PermissionBasedAccessControlService } from './permission-based-access-control.service.js'

export interface PermissionsGuardOptions {
  mode: 'one' | 'all'
}

export function PermissionsGuard (permissions: string | string[], options?: PermissionsGuardOptions): Type<CanActivate> {
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
