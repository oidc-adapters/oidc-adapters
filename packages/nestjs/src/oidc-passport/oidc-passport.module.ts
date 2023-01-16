import type {
  CanActivate,
  DynamicModule,
  InjectionToken,
  ModuleMetadata,
  OptionalFactoryDependency,
  Provider,
  Type
} from '@nestjs/common'
import { Module } from '@nestjs/common'
import type { StrategyOptions, VerifyCallback, VerifyCallbackWithRequest } from '@oidc-adapters/passport'
import { Strategy } from '@oidc-adapters/passport'
import { AuthGuard, PassportStrategy } from '@nestjs/passport'
import { APP_GUARD } from '@nestjs/core'
import { OptionalAuthGuard } from './optional-auth.guard.js'

export const OIDC_PASSPORT_OPTIONS = Symbol('OidcPassportOptions')

export interface OidcPassportOptions {
  options: StrategyOptions,
  verify?: VerifyCallback | VerifyCallbackWithRequest,
  strategyName?: string
  appGuard?: boolean | 'optional'
}

export interface OidcPassportOptionsFactory {
  createOidcPassportOptions (): Promise<OidcPassportOptions> | OidcPassportOptions;
}

export interface OidcPassportAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  inject?: (InjectionToken | OptionalFactoryDependency)[];
  useClass?: Type<OidcPassportOptionsFactory>
  useExisting?: Type<OidcPassportOptionsFactory>
  useFactory?: (...arguments_: never[]) => Promise<OidcPassportOptions> | OidcPassportOptions
  extraProviders?: Provider[]
}

/**
 * Configuration module for @oidc-adapters passport strategy.
 */
@Module({})
export class OidcPassportModule {
  private static createProviders (options: OidcPassportOptions, feature?: string): Provider[] {
    return [this.createOptionsProvider(options), this.createPassportStrategyProvider(feature), this.createAppGuardProvider()]
  }

  private static createAsyncProviders (options: OidcPassportAsyncOptions, feature?: string): Provider[] {
    const providers: Provider[] = [this.createAsyncOptionsProvider(options), this.createPassportStrategyProvider(feature), this.createAppGuardProvider(), ...(options.extraProviders ?? [])]

    if (options.useClass) {
      providers.push({
        provide: options.useClass,
        useClass: options.useClass
      })
    }

    return providers
  }

  private static createOptionsProvider (options: OidcPassportOptions): Provider {
    return {
      provide: OIDC_PASSPORT_OPTIONS,
      useValue: options
    }
  }

  private static createAsyncOptionsProvider (options: OidcPassportAsyncOptions): Provider {
    if (options.useFactory) {
      return {
        provide: OIDC_PASSPORT_OPTIONS,
        useFactory: options.useFactory,
        inject: options.inject || []
      }
    }

    const inject = options.useExisting ?? options.useClass

    if (!inject) {
      throw new Error('At least one of useFactory, useExisting or useClass option should be defined')
    }

    return {
      provide: OIDC_PASSPORT_OPTIONS,
      useFactory: async (optionsFactory: OidcPassportOptionsFactory) => {
        return optionsFactory.createOidcPassportOptions()
      },
      inject: [inject]
    }
  }

  private static createPassportStrategyProvider (feature?: string): Provider {
    return {
      provide: `OidcPassportStrategy${feature ? `<${feature}>` : ''}`,
      inject: [OIDC_PASSPORT_OPTIONS],
      useFactory: (options: OidcPassportOptions) => {
        class StrategyInstance extends PassportStrategy(Strategy, options.strategyName) {
          constructor () {
            super(options.options, options.verify)
          }
        }

        return new StrategyInstance()
      }
    }
  }

  private static createAppGuardProvider (): Provider {
    return {
      provide: APP_GUARD,
      inject: [OIDC_PASSPORT_OPTIONS],
      useFactory: (options: OidcPassportOptions): Type<CanActivate> | CanActivate | undefined => {
        if (options.appGuard === 'optional') {
          return OptionalAuthGuard(options.strategyName ?? 'oidc')
        } else if (options.appGuard) {
          return AuthGuard(options.strategyName ?? 'oidc')
        }
      }
    }
  }

  static forRoot (options: OidcPassportOptions): DynamicModule {
    return {
      module: OidcPassportModule,
      providers: this.createProviders(options)
    }
  }

  static forRootAsync (options: OidcPassportAsyncOptions): DynamicModule {
    return {
      module: OidcPassportModule,
      imports: options.imports,
      providers: this.createAsyncProviders(options)
    }
  }

  static forFeature (options: OidcPassportOptions & { feature?: string }): DynamicModule {
    return {
      module: OidcPassportModule,
      providers: this.createProviders(options, options.feature ?? options.strategyName ?? 'oidc')
    }
  }

  static forFeatureAsync (options: OidcPassportAsyncOptions & { feature: string }): DynamicModule {
    return {
      module: OidcPassportModule,
      imports: options.imports,
      providers: this.createAsyncProviders(options, options.feature)
    }
  }

  static register = (options: OidcPassportOptions) => OidcPassportModule.forFeature(options)

  static registerAsync = (options: OidcPassportAsyncOptions & { feature: string }) => OidcPassportModule.forFeatureAsync(options)
}
