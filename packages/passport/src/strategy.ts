/* eslint-disable promise/no-callback-in-promise */

import type {
  StrategyOptions as JwtStrategyOptions,
  VerifyCallback as JwtVerifyCallback,
  VerifyCallbackWithRequest as JwtVerifyCallbackWithRequest
} from 'passport-jwt'
import { ExtractJwt, Strategy as JwtStrategy } from 'passport-jwt'
import type { KeyProviderOptions } from '@oidc-adapters/core'
import { KeyProvider } from '@oidc-adapters/core'
// eslint-disable-next-line n/no-unpublished-import
import type { IdTokenClaims } from 'oidc-client-ts'

export interface StrategyOptions extends Omit<Partial<JwtStrategyOptions>, 'secretOrKeyProvider'>, KeyProviderOptions {

}

export type VerifyCallback = JwtVerifyCallback
export type VerifyCallbackWithRequest = JwtVerifyCallbackWithRequest

export interface User extends Express.User {
  jwtPayload: IdTokenClaims
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface User {
      jwtPayload: IdTokenClaims
    }
  }
}

export const defaultJwtFromRequest = ExtractJwt.fromExtractors([ExtractJwt.fromAuthHeaderAsBearerToken()])

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
      ...opt
    }

    const efffectiveVerify: VerifyCallbackWithRequest | VerifyCallback = verify ?? ((jwtPayload: IdTokenClaims, done) => done(undefined, { jwtPayload } as User)) as VerifyCallback

    super(effectiveOptions, efffectiveVerify)
  }
}
