import type { CanActivate, DynamicModule, InjectionToken, ModuleMetadata, OptionalFactoryDependency, Provider, Type } from '@nestjs/common'
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

export const ROLE_BASED_ACCESS_CONTROL_OPTIONS = Symbol('RoleBasedAccessControlOptions')

export type RoleBasedAccessControlOptions = RoleBasedAccessControlServiceOptions & {
  defaults?: RolesGuardOptions
  decorators?: boolean
}

export interface RoleBasedAccessControlOptionsFactory {
  createRoleBasedAccessControlOptions (): Promise<RoleBasedAccessControlOptions> | RoleBasedAccessControlOptions;
}

export interface RoleBasedAccessControlAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  inject?: (InjectionToken | OptionalFactoryDependency)[];
  useClass?: Type<RoleBasedAccessControlOptionsFactory>
  useExisting?: Type<RoleBasedAccessControlOptionsFactory>
  useFactory?: (...arguments_: never[]) => Promise<RoleBasedAccessControlOptions> | RoleBasedAccessControlOptions
  extraProviders?: Provider[]
}

/**
 * Configuration module for @oidc-adapters passport strategy.
 */
@Module({})
export class RoleBasedAccessControlModule {
  private static createProviders (options: RoleBasedAccessControlOptions): Provider[] {
    return [this.createOptionsProvider(options), this.createServiceOptionsProvider(), this.createRolesGuardOptionsProvider(), this.createAppGuardProvider()]
  }

  private static createAsyncProviders (options: RoleBasedAccessControlAsyncOptions): Provider[] {
    return [this.createAsyncOptionsProvider(options), this.createServiceOptionsProvider(), this.createRolesGuardOptionsProvider(), this.createAppGuardProvider(), ...(options.extraProviders ?? [])]
  }

  private static createOptionsProvider (options: RoleBasedAccessControlOptions): Provider {
    return {
      provide: ROLE_BASED_ACCESS_CONTROL_OPTIONS,
      useValue: options
    }
  }

  private static createAsyncOptionsProvider (options: RoleBasedAccessControlAsyncOptions): Provider {
    if (options.useFactory) {
      return {
        provide: ROLE_BASED_ACCESS_CONTROL_OPTIONS,
        useFactory: options.useFactory,
        inject: options.inject || []
      }
    }

    const inject = options.useExisting ?? options.useClass

    if (!inject) {
      throw new Error('At least one of useFactory, useExisting or useClass option should be defined')
    }

    return {
      provide: ROLE_BASED_ACCESS_CONTROL_OPTIONS,
      useFactory: async (optionsFactory: RoleBasedAccessControlOptionsFactory) => {
        return optionsFactory.createRoleBasedAccessControlOptions()
      },
      inject: [inject]
    }
  }

  private static createRolesGuardOptionsProvider (): Provider {
    return {
      provide: ROLES_GUARD_OPTIONS,
      inject: [ROLE_BASED_ACCESS_CONTROL_OPTIONS],
      useFactory: (options: RoleBasedAccessControlOptions) => {
        return options.defaults
      }
    }
  }

  private static createServiceOptionsProvider (): Provider {
    return {
      provide: ROLE_BASED_ACCESS_CONTROL_SERVICE_OPTIONS,
      inject: [ROLE_BASED_ACCESS_CONTROL_OPTIONS],
      useFactory: (options: RoleBasedAccessControlOptions) => {
        return options
      }
    }
  }

  private static createAppGuardProvider (): Provider {
    return {
      provide: APP_GUARD,
      inject: [ROLE_BASED_ACCESS_CONTROL_OPTIONS, RolesDecoratorsGuard],
      useFactory: (options: RoleBasedAccessControlOptions, guard: RolesDecoratorsGuard): CanActivate | undefined => {
        if (options.decorators !== false) {
          return guard
        }
      }
    }
  }

  static forRoot (options: RoleBasedAccessControlOptions): DynamicModule {
    return {
      module: RoleBasedAccessControlModule,
      providers: [
        ...this.createProviders(options),
        RolesDecoratorsGuard,
        RoleBasedAccessControlService
      ],
      exports: [RoleBasedAccessControlService, RolesDecoratorsGuard]
    }
  }

  static forRootAsync (options: RoleBasedAccessControlAsyncOptions): DynamicModule {
    return {
      module: RoleBasedAccessControlModule,
      providers: [
        ...this.createAsyncProviders(options),
        RolesDecoratorsGuard,
        RoleBasedAccessControlService
      ],
      exports: [RoleBasedAccessControlService, RolesDecoratorsGuard]
    }
  }
}
