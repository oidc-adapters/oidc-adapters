import type { DynamicModule } from '@nestjs/common'
import { Module } from '@nestjs/common'
import type { RoleBasedAccessControlServiceOptions } from './role-based-access-control.service.js'
import {
  ROLE_BASED_ACCESS_CONTROL_SERVICE_OPTIONS,
  RoleBasedAccessControlService
} from './role-based-access-control.service.js'
import type { RolesGuardOptions } from './roles.guard.js'
import { ROLES_GUARD_OPTIONS } from './roles.guard.js'
import { APP_GUARD } from '@nestjs/core'
import { RolesDecoratorsGuard } from './roles-decorators.guard.js'

export type RoleBasedAccessControlModuleOptions = RoleBasedAccessControlServiceOptions & {
  defaults?: RolesGuardOptions
  decorators?: boolean
}

/**
 * Configuration module for @oidc-adapters passport strategy.
 */
@Module({})
export class RoleBasedAccessControlModule {
  static forRoot (options: RoleBasedAccessControlModuleOptions): DynamicModule {
    const serviceOptions: RoleBasedAccessControlServiceOptions = {
      providerType: options.providerType,
      provider: options.provider
    } as RoleBasedAccessControlServiceOptions

    const module: DynamicModule = {
      module: RoleBasedAccessControlModule,
      providers: [
        {
          provide: ROLE_BASED_ACCESS_CONTROL_SERVICE_OPTIONS,
          useValue: serviceOptions
        },
        {
          provide: ROLES_GUARD_OPTIONS,
          useValue: options.defaults
        },
        RolesDecoratorsGuard,
        RoleBasedAccessControlService
      ],
      exports: [RoleBasedAccessControlService, RolesDecoratorsGuard]
    }

    if (options.decorators !== false) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      module.providers!.push({
        provide: APP_GUARD,
        useClass: RolesDecoratorsGuard
      })
    }

    return module
  }
}
