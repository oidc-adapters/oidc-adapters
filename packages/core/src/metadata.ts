import type { OidcClientSettings } from 'oidc-client-ts'
import { MetadataService, OidcClientSettingsStore } from 'oidc-client-ts'

export type MetadataOptions = Partial<Pick<OidcClientSettings, 'authority' | 'metadataUrl'>>

export function createMetadataService (settings: MetadataOptions) {
  const oidcClientSettingsStore = new OidcClientSettingsStore({
    authority: '',
    client_id: '',
    redirect_uri: '',
    ...settings
  })

  return new MetadataService(oidcClientSettingsStore)
}
