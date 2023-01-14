import type { DynamicModule } from '@nestjs/common'
import { Module } from '@nestjs/common'
import type { StrategyOptions, VerifyCallbackWithRequest } from '@oidc-adapters/passport'
import { Strategy } from '@oidc-adapters/passport'
import type { VerifyCallback } from '@oidc-adapters/passport/src/index.js'
import { AuthGuard, PassportStrategy } from '@nestjs/passport'
import { APP_GUARD } from '@nestjs/core'
import { OptionalAuthGuard } from './optional-auth.guard.js'

export interface OidcPassportModuleOptions {
  options: StrategyOptions,
  verify?: VerifyCallback | VerifyCallbackWithRequest,
  strategyName?: string,
  appGuard?: boolean | 'optional'
}

function applyAppGuard (module: DynamicModule, appGuard: OidcPassportModuleOptions['appGuard'], effectiveStrategyName = 'oidc') {
  if (!appGuard) return

  if (module.providers === undefined) module.providers = []
  if (appGuard === 'optional') {
    module.providers.push({
      provide: APP_GUARD,
      useClass: OptionalAuthGuard(AuthGuard(effectiveStrategyName))
    })
  } else {
    module.providers.push({
      provide: APP_GUARD,
      useClass: AuthGuard(effectiveStrategyName)
    })
  }
}

/**
 * Configuration module for @oidc-adapters passport strategy.
 */
@Module({})
export class OidcPassportModule {
  static forRoot (options: OidcPassportModuleOptions): DynamicModule {
    const module: DynamicModule = {
      module: OidcPassportModule,
      providers: [
        {
          provide: 'OidcPassportStrategy',
          useFactory: () => {
            class StrategyInstance extends PassportStrategy(Strategy, options.strategyName) {
              constructor () {
                super(options.options, options.verify)
              }
            }

            return new StrategyInstance()
          }
        }
      ]
    }

    applyAppGuard(module, options.appGuard, options.strategyName)

    return module
  }

  static forFeature (options: OidcPassportModuleOptions): DynamicModule {
    const module: DynamicModule = {
      module: OidcPassportModule,
      providers: [
        {
          provide: `OidcPassportStrategy<${options.strategyName ?? 'oidc'}>`,
          useFactory: () => {
            class StrategyInstance extends PassportStrategy(Strategy, options.strategyName) {
              constructor () {
                super(options.options, options.verify)
              }
            }

            return new StrategyInstance()
          }
        }
      ]
    }

    applyAppGuard(module, options.appGuard, options.strategyName)

    return module
  }

  static register = (options: OidcPassportModuleOptions) => OidcPassportModule.forFeature(options)
}
