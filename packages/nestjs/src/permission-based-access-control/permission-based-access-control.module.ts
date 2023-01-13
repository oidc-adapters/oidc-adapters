import type { DynamicModule } from '@nestjs/common'
import { Module } from '@nestjs/common'
import type { PermissionBasedAccessControlServiceOptions } from './permission-based-access-control.service.js'
import { PermissionBasedAccessControlService, SERVICE_OPTIONS } from './permission-based-access-control.service.js'

/**
 * Configuration module for @oidc-adapters passport strategy.
 */
@Module({})
export class PermissionBasedAccessControlModule {
  static forRoot (options: PermissionBasedAccessControlServiceOptions): DynamicModule {
    return {
      module: PermissionBasedAccessControlModule,
      providers: [
        {
          provide: SERVICE_OPTIONS,
          useValue: options
        },
        PermissionBasedAccessControlService
      ],
      exports: [PermissionBasedAccessControlService, SERVICE_OPTIONS]
    }
  }
}
