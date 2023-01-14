import jwt from 'jsonwebtoken'
import { createMetadataService } from './metadata.js'
import type { JWK } from 'jwk-to-pem'
import jwkToPem from 'jwk-to-pem'
import type { JwtClaims, SigningKey } from 'oidc-client-ts'

export type IssuerCheckSpec = (string | RegExp)[] | ((issuer: string) => boolean)

export interface KeyProviderOptions {
  allowedIssuers: IssuerCheckSpec
  deniedIssuers?: IssuerCheckSpec
}

export class KeyProviderError extends Error {}

interface CacheEntry {
  keys: SigningKey[],
  pem: Map<string, string>
}

export class KeyProvider {
  private keysCache: Map<string, CacheEntry> = new Map()

  constructor (private options: KeyProviderOptions) {
  }

  clearCache () {
    this.keysCache.clear()
  }

  private evaluateIssuerSpec (issuer: string, spec?: IssuerCheckSpec) {
    if (typeof spec === 'function') {
      if (spec(issuer)) {
        return true
      }
    } else if (spec) {
      for (const specIssuer of spec) {
        if (typeof specIssuer === 'string') {
          if (specIssuer === issuer) {
            return true
          }
        } else {
          if (specIssuer.test(issuer)) {
            return true
          }
        }
      }
    }

    return false
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

    const allowed = this.evaluateIssuerSpec(issuer, this.options.allowedIssuers)
    const denied = this.evaluateIssuerSpec(issuer, this.options.deniedIssuers)

    if (!allowed) {
      throw new KeyProviderError(`Token issuer "${issuer}" is not allowed`)
    }

    if (denied) {
      throw new KeyProviderError(`Token issuer "${issuer}" is denied`)
    }

    let newKeys: SigningKey[] | undefined
    let cacheEntry = this.getCacheEntry(issuer)
    if (!cacheEntry) {
      cacheEntry = await this.downloadAndCacheIssuerKeys(issuer)
    }

    if (!decoded.header.kid) {
      throw new KeyProviderError('Token key id is not defined')
    }

    let matchingKey = this.findMatchingKey(cacheEntry.keys, decoded.header.kid)
    if (!matchingKey && !newKeys) {
      // Refresh keys from issuer source if no matching key is found and current keys were loaded from cache.
      cacheEntry = await this.downloadAndCacheIssuerKeys(issuer)

      matchingKey = this.findMatchingKey(cacheEntry.keys, decoded.header.kid)
    }

    if (!matchingKey) {
      throw new KeyProviderError(`No key matching key id "${decoded.header.kid}" found for issuer ${issuer}`)
    }

    let cachePem = cacheEntry.pem.get(decoded.header.kid)
    if (!cachePem) {
      cachePem = jwkToPem(matchingKey as unknown as JWK)
      cacheEntry.pem.set(decoded.header.kid, cachePem)
    }

    return cachePem
  }

  private async downloadAndCacheIssuerKeys (issuer: string): Promise<CacheEntry> {
    const metadataService = createMetadataService({ authority: issuer })
    const newKeys = await metadataService.getSigningKeys()

    if (!newKeys) {
      throw new KeyProviderError(`No keys found for issuer ${issuer}`)
    }

    const newCacheEntry = { keys: newKeys, pem: new Map() }
    this.keysCache.set(issuer, newCacheEntry)

    return newCacheEntry
  }

  private getCacheEntry (issuer: string): CacheEntry | undefined {
    return this.keysCache.get(issuer)
  }

  private findMatchingKey (keys: SigningKey[], kid: string) {
    return keys.find(key => typeof key.kid === 'string' ? key.kid === kid : key.kid.includes(kid))
  }
}
