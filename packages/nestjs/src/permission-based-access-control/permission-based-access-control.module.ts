import type { CanActivate, DynamicModule, InjectionToken, ModuleMetadata, OptionalFactoryDependency, Provider, Type } from '@nestjs/common'
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

export const PERMISSION_BASED_ACCESS_CONTROL_OPTIONS = Symbol('PermissionBasedAccessControlOptions')

export type PermissionBasedAccessControlOptions = PermissionBasedAccessControlServiceOptions & {
  defaults?: PermissionsGuardOptions
  decorators?: boolean
}

export interface PermissionBasedAccessControlOptionsFactory {
  createPermissionBasedAccessControlOptions (): Promise<PermissionBasedAccessControlOptions> | PermissionBasedAccessControlOptions;
}

export interface PermissionBasedAccessControlAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  inject?: (InjectionToken | OptionalFactoryDependency)[];
  useClass?: Type<PermissionBasedAccessControlOptionsFactory>
  useExisting?: Type<PermissionBasedAccessControlOptionsFactory>
  useFactory?: (...arguments_: never[]) => Promise<PermissionBasedAccessControlOptions> | PermissionBasedAccessControlOptions
  extraProviders?: Provider[]
}

/**
 * Configuration module for @oidc-adapters passport strategy.
 */
@Module({})
export class PermissionBasedAccessControlModule {
  private static createProviders (options: PermissionBasedAccessControlOptions): Provider[] {
    return [this.createOptionsProvider(options), this.createServiceOptionsProvider(), this.createPermissionsGuardOptionsProvider(), this.createAppGuardProvider()]
  }

  private static createAsyncProviders (options: PermissionBasedAccessControlAsyncOptions): Provider[] {
    return [this.createAsyncOptionsProvider(options), this.createServiceOptionsProvider(), this.createPermissionsGuardOptionsProvider(), this.createAppGuardProvider(), ...(options.extraProviders ?? [])]
  }

  private static createOptionsProvider (options: PermissionBasedAccessControlOptions): Provider {
    return {
      provide: PERMISSION_BASED_ACCESS_CONTROL_OPTIONS,
      useValue: options
    }
  }

  private static createAsyncOptionsProvider (options: PermissionBasedAccessControlAsyncOptions): Provider {
    if (options.useFactory) {
      return {
        provide: PERMISSION_BASED_ACCESS_CONTROL_OPTIONS,
        useFactory: options.useFactory,
        inject: options.inject || []
      }
    }

    const inject = options.useExisting ?? options.useClass

    if (!inject) {
      throw new Error('At least one of useFactory, useExisting or useClass option should be defined')
    }

    return {
      provide: PERMISSION_BASED_ACCESS_CONTROL_OPTIONS,
      useFactory: async (optionsFactory: PermissionBasedAccessControlOptionsFactory) => {
        return optionsFactory.createPermissionBasedAccessControlOptions()
      },
      inject: [inject]
    }
  }

  private static createServiceOptionsProvider (): Provider {
    return {
      provide: PERMISSION_BASED_ACCESS_CONTROL_SERVICE_OPTIONS,
      inject: [PERMISSION_BASED_ACCESS_CONTROL_OPTIONS],
      useFactory: (options: PermissionBasedAccessControlOptions) => {
        return options
      }
    }
  }

  private static createPermissionsGuardOptionsProvider (): Provider {
    return {
      provide: PERMISSIONS_GUARD_OPTIONS,
      inject: [PERMISSION_BASED_ACCESS_CONTROL_OPTIONS],
      useFactory: (options: PermissionBasedAccessControlOptions) => {
        return options.defaults
      }
    }
  }

  private static createAppGuardProvider (): Provider {
    return {
      provide: APP_GUARD,
      inject: [PERMISSION_BASED_ACCESS_CONTROL_OPTIONS, PermissionsDecoratorsGuard],
      useFactory: (options: PermissionBasedAccessControlOptions, guard: PermissionsDecoratorsGuard): CanActivate | undefined => {
        if (options.decorators !== false) {
          return guard
        }
      }
    }
  }

  static forRoot (options: PermissionBasedAccessControlOptions): DynamicModule {
    return {
      module: PermissionBasedAccessControlModule,
      providers: [
        ...this.createProviders(options),
        PermissionsDecoratorsGuard,
        PermissionBasedAccessControlService
      ],
      exports: [PermissionBasedAccessControlService, PermissionsDecoratorsGuard]
    }
  }

  static forRootAsync (options: PermissionBasedAccessControlAsyncOptions): DynamicModule {
    return {
      module: PermissionBasedAccessControlModule,
      imports: options.imports,
      providers: [
        ...this.createAsyncProviders(options),
        PermissionsDecoratorsGuard,
        PermissionBasedAccessControlService
      ],
      exports: [PermissionBasedAccessControlService, PermissionsDecoratorsGuard]
    }
  }
}
