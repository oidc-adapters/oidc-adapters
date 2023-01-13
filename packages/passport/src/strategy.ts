/* eslint-disable promise/no-callback-in-promise */

import type {
  StrategyOptions as JwtStrategyOptions,
  VerifiedCallback,
  VerifyCallback as JwtVerifyCallback,
  VerifyCallbackWithRequest as JwtVerifyCallbackWithRequest
} from 'passport-jwt'
import { ExtractJwt, Strategy as JwtStrategy } from 'passport-jwt'
import type { KeyProviderOptions } from '@oidc-adapters/core'
import { KeyProvider } from '@oidc-adapters/core'
// eslint-disable-next-line n/no-unpublished-import
import type { IdTokenClaims } from 'oidc-client-ts'
import type * as express from 'express'

export interface StrategyOptions extends Omit<Partial<JwtStrategyOptions>, 'secretOrKeyProvider'>, KeyProviderOptions {

}

export interface VerifyCallback<T = IdTokenClaims> {
  (payload: T, done: VerifiedCallback): void;
}

export interface VerifyCallbackWithRequest<T = IdTokenClaims> {
  (request: express.Request, payload: T, done: VerifiedCallback): void;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface User {
      jwtPayload: IdTokenClaims
      jwt: string
    }
  }
}

export const defaultJwtFromRequest = ExtractJwt.fromExtractors([ExtractJwt.fromAuthHeaderAsBearerToken()])

export const defaultVerifyFactory: (options: JwtStrategyOptions) => VerifyCallbackWithRequest = (options) => (request, jwtPayload: IdTokenClaims, done) => {
  try {
    const jwt = options.jwtFromRequest(request)
    done(undefined, { jwtPayload, jwt } as Express.User)
  } catch (error) {
    done(error)
  }
}

export class Strategy extends JwtStrategy {
  name = 'oidc'

  constructor (opt: StrategyOptions, verify?: VerifyCallbackWithRequest)
  constructor (opt: StrategyOptions, verify?: VerifyCallback)
  constructor (opt: StrategyOptions, verify?: VerifyCallbackWithRequest | VerifyCallback) {
    const keyProvider = new KeyProvider(opt)

    const effectiveOptions: JwtStrategyOptions = {
      jwtFromRequest: defaultJwtFromRequest,
      secretOrKeyProvider: (_, rawJwtToken: string, done) => {
        keyProvider.getPublicKey(rawJwtToken).then((publicKey) => {
          done(undefined, publicKey)
          return publicKey
        }).catch(done)
      },
      passReqToCallback: verify !== undefined ? undefined : true,
      ...opt
    }

    const efffectiveVerify: JwtVerifyCallbackWithRequest | JwtVerifyCallback = verify ?? defaultVerifyFactory(effectiveOptions)

    super(effectiveOptions, efffectiveVerify)
  }
}
