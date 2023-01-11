import type { MetadataService, OidcClientSettings } from 'oidc-client-ts'
import type { MetadataOptions } from './metadata.js'
import { createMetadataService } from './metadata.js'

export class DirectGrantError extends Error {

}

export type DirectGrantOptions =
  MetadataOptions
  & Pick<OidcClientSettings, 'client_id' | 'client_secret' | 'scope'>

/**
 * https://www.ietf.org/rfc/rfc6749.txt
 * 4.2.2.  Access Token Response
 * 5.1.  Successful Response
 */
export interface DirectGrantResponse {
  [key: string]: unknown,

  access_token: string
  token_type: string,
  expires_in?: number,
  refresh_token?: string
  scopes?: string
}

export class DirectGrant {
  private metadataService: MetadataService

  constructor (private options: DirectGrantOptions) {
    this.metadataService = createMetadataService(options)
  }

  async password (username: string, password: string): Promise<DirectGrantResponse> {
    const tokenEndpoint = await this.metadataService.getTokenEndpoint()
    if (tokenEndpoint === undefined) throw new DirectGrantError('No token endpoint')

    const body = new URLSearchParams()

    body.append('grant_type', 'password')
    body.append('client_id', this.options.client_id)
    if (this.options.client_secret) {
      body.append('client_id', this.options.client_secret)
    }
    if (this.options.scope) {
      body.append('scope', this.options.scope)
    }

    body.append('username', username)
    body.append('password', password)

    const tokenResponse = await fetch(tokenEndpoint, {
      method: 'post',
      body
    })

    return await tokenResponse.json() as DirectGrantResponse
  }
}
