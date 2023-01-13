import type { DirectGrantOptions } from '@oidc-adapters/core'
import { DirectGrant } from '@oidc-adapters/core'
import type { Plugin } from 'superagent'

const defaultDirectGrantOptions: DirectGrantOptions = {
  authority: 'http://localhost:8109/realms/keycloak-test',
  client_id: 'app-authorization-services-test',
  client_secret: 'etkjHLXBRPpYSdebPqLM9XrPvkOzbv2d',
  scope: 'openid'
}

export async function directGrant (username: string, password: string, options?: DirectGrantOptions): Promise<Plugin> {
  const directGrant = new DirectGrant({ ...defaultDirectGrantOptions, ...options })
  const tokenReponseJson = await directGrant.password(username, password)
  const accessToken = tokenReponseJson.access_token
  if (!accessToken) {
    throw new Error('Invalid authentication')
  }
  // eslint-disable-next-line @typescript-eslint/no-misused-promises
  const plugin: Plugin = async (request) => {
    await request.set('Authorization', `Bearer ${accessToken}`)
  }
  return plugin
}
