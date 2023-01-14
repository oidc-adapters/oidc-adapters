import type { DynamicModule } from '@nestjs/common'
import { Module } from '@nestjs/common'
import type { PermissionBasedAccessControlServiceOptions } from './permission-based-access-control.service.js'
import {
  PERMISSION_BASED_ACCESS_CONTROL_SERVICE_OPTIONS,
  PermissionBasedAccessControlService
} from './permission-based-access-control.service.js'
import { APP_GUARD } from '@nestjs/core'
import { PermissionsDecoratorsGuard } from './permissions-decorators.guard.js'
import type { PermissionsGuardOptions } from './permissions.guard.js'
import { PERMISSIONS_GUARD_OPTIONS } from './permissions.guard.js'

export type PermissionBasedAccessControlModuleOptions = PermissionBasedAccessControlServiceOptions & {
  defaults?: PermissionsGuardOptions
  decorators?: boolean
}

/**
 * Configuration module for @oidc-adapters passport strategy.
 */
@Module({})
export class PermissionBasedAccessControlModule {
  static forRoot (options: PermissionBasedAccessControlModuleOptions): DynamicModule {
    const module: DynamicModule = {
      module: PermissionBasedAccessControlModule,
      providers: [
        {
          provide: PERMISSION_BASED_ACCESS_CONTROL_SERVICE_OPTIONS,
          useValue: options
        },
        {
          provide: PERMISSIONS_GUARD_OPTIONS,
          useValue: options.defaults
        },
        PermissionsDecoratorsGuard,
        PermissionBasedAccessControlService
      ],
      exports: [PermissionBasedAccessControlService, PermissionsDecoratorsGuard]
    }

    if (options.decorators !== false) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      module.providers!.push({
        provide: APP_GUARD,
        useClass: PermissionsDecoratorsGuard
      })
    }

    return module
  }
}
