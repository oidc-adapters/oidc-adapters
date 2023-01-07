import jwt from 'jsonwebtoken'
import { createMetadataService } from './metadata.js'
import type { JWK } from 'jwk-to-pem'
import jwkToPem from 'jwk-to-pem'
import type { JwtClaims } from 'oidc-client-ts'

export interface KeyProviderOptions {
  allowedIssuers: string[] | ((issuer: string) => boolean)
}

export class KeyProviderError extends Error {}

export class KeyProvider {
  constructor (private options: KeyProviderOptions) {
  }

  async getPublicKey (token: string): Promise<string> {
    // eslint-disable-next-line import/no-named-as-default-member
    const decoded = jwt.decode(token, { complete: true })
    if (!decoded) {
      throw new KeyProviderError(`Can\t decode token ${token}`)
    }

    const issuer = (decoded.payload as JwtClaims).iss
    if (issuer === undefined) {
      throw new KeyProviderError('Token issuer is not defined')
    }

    let allowed = true
    if (typeof this.options.allowedIssuers === 'function') {
      if (!this.options.allowedIssuers(issuer)) {
        allowed = false
      }
    } else if (!this.options.allowedIssuers.includes(issuer)) {
      allowed = false
    }
    if (!allowed) {
      throw new KeyProviderError(`Token issuer "${issuer}" is not allowed`)
    }

    const metadataService = createMetadataService({ authority: issuer })
    const keys = await metadataService.getSigningKeys()

    if (!keys) {
      throw new KeyProviderError(`No keys found for authority ${issuer}`)
    }

    const matchingKey = keys.find(k => k.kid === decoded.header.kid)
    if (!matchingKey) {
      throw new KeyProviderError(`No key matching kid=${decoded.header.kid} found for authority ${issuer}`)
    }

    return jwkToPem(matchingKey as unknown as JWK)
  }
}
