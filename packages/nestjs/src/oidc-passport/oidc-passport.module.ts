import type { DynamicModule } from '@nestjs/common'
import { Module } from '@nestjs/common'
import type { StrategyOptions, VerifyCallbackWithRequest } from '@oidc-adapters/passport'
import { Strategy } from '@oidc-adapters/passport'
import type { VerifyCallback } from '@oidc-adapters/passport/src/index.js'
import { PassportStrategy } from '@nestjs/passport'

export interface OidcPassportModuleOptions {
  options: StrategyOptions,
  verify?: VerifyCallback | VerifyCallbackWithRequest,
  strategyName?: string
}

/**
 * Configuration module for @oidc-adapters passport strategy.
 */
@Module({})
export class OidcPassportModule {
  static forRoot (options: OidcPassportModuleOptions): DynamicModule {
    return {
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
  }

  static forFeature (options: OidcPassportModuleOptions): DynamicModule {
    return {
      module: OidcPassportModule,
      providers: [
        {
          provide: `OidcPassportStrategy${options.strategyName ?? 'oidc'}`,
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
  }

  static register = (options: OidcPassportModuleOptions) => OidcPassportModule.forFeature(options)
}
