/* eslint-disable promise/no-callback-in-promise */

import type { StrategyOptions as JwtStrategyOptions, VerifyCallback } from 'passport-jwt'
import { ExtractJwt, Strategy as JwtStrategy } from 'passport-jwt'
import { KeyProvider } from '@oidc-adapters/core'
// eslint-disable-next-line n/no-unpublished-import
import type { IdTokenClaims } from 'oidc-client-ts'
import type { KeyProviderOptions } from '@oidc-adapters/core/src/index.js'

export interface StrategyOptions extends KeyProviderOptions {
  verify?: VerifyCallback
  jwt?: JwtStrategyOptions
}

export interface User extends Express.User {
  jwtPayload: IdTokenClaims
}

export function createStrategy (options: StrategyOptions): JwtStrategy {
  const keyProvider = new KeyProvider(options)

  const jwtStrategyOptions: JwtStrategyOptions = {
    jwtFromRequest: ExtractJwt.fromExtractors([ExtractJwt.fromAuthHeaderAsBearerToken(), ExtractJwt.fromUrlQueryParameter('bearer')]),
    secretOrKeyProvider: (_, rawJwtToken: string, done) => {
      keyProvider.getPublicKey(rawJwtToken).then((publicKey) => {
        done(undefined, publicKey)
        return publicKey
      }).catch(done)
    },
    ...options?.jwt
  }

  const jwtStrategy = new JwtStrategy(jwtStrategyOptions, options?.verify ?? ((jwtPayload: IdTokenClaims, done) => done(undefined, { jwtPayload } as User)))
  jwtStrategy.name = 'oidc'
  return jwtStrategy
}
