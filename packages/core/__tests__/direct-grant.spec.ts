/* eslint-disable unicorn/numeric-separators-style,quote-props */
import { DirectGrant } from '../src/direct-grant.js'

describe('direct-grant.ts', function () {
  it('should retrieve access token', async () => {
    const directGrant = new DirectGrant({
      authority: 'http://localhost:8109/realms/master',
      client_id: 'admin-cli'
    })

    const tokenReponseJson = await directGrant.password('admin', 'admin')
    const accessToken = tokenReponseJson?.access_token
    expect(accessToken).toBeDefined()
  })
})
