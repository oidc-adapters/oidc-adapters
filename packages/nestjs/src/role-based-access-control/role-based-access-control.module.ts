import type { DynamicModule } from '@nestjs/common'
import { Module } from '@nestjs/common'
import type { RoleBasedAccessControlServiceOptions } from './role-based-access-control.service.js'
import { RoleBasedAccessControlService, SERVICE_OPTIONS } from './role-based-access-control.service.js'

/**
 * Configuration module for @oidc-adapters passport strategy.
 */
@Module({})
export class RoleBasedAccessControlModule {
  static forRoot (options: RoleBasedAccessControlServiceOptions): DynamicModule {
    return {
      module: RoleBasedAccessControlModule,
      providers: [
        {
          provide: SERVICE_OPTIONS,
          useValue: options
        },
        RoleBasedAccessControlService
      ],
      exports: [RoleBasedAccessControlService, SERVICE_OPTIONS]
    }
  }
}
