import { createMetadataService } from '../src/metadata.js'

describe('metadata.ts', function () {
  it('Should get metadata from authority', async () => {
    const metadataService = createMetadataService({ authority: 'http://localhost:8109/realms/master' })

    const metadata = await metadataService.getMetadata()

    expect(metadata.authorization_endpoint).toEqual('http://localhost:8109/realms/master/protocol/openid-connect/auth')

    expect(await metadataService.getAuthorizationEndpoint()).toEqual('http://localhost:8109/realms/master/protocol/openid-connect/auth')
  })

  it('Should get metadata from metadataUrl', async () => {
    const metadataService = createMetadataService({ metadataUrl: 'http://localhost:8109/realms/master/.well-known/openid-configuration' })

    const metadata = await metadataService.getMetadata()

    expect(metadata.authorization_endpoint).toEqual('http://localhost:8109/realms/master/protocol/openid-connect/auth')

    expect(await metadataService.getAuthorizationEndpoint()).toEqual('http://localhost:8109/realms/master/protocol/openid-connect/auth')
  })

  it('Should fail to create metadata if neither is defined', async () => {
    const metadataService = createMetadataService({})

    await expect(metadataService.getMetadata()).rejects.toThrow('No authority or metadataUrl configured on settings')
  })
})
