import type { MetadataService, OidcClientSettings } from 'oidc-client-ts'
import type { MetadataOptions } from './metadata.js'
import { createMetadataService } from './metadata.js'

export class DirectGrantError extends Error {

}

export type DirectGrantOptions =
  MetadataOptions
  & Pick<OidcClientSettings, 'client_id' | 'client_secret' | 'scope'>

export interface DirectGrantResponse {
  [key: string]: unknown,
  access_token: string
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
