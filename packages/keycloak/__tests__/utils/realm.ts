/**
 * A wrapper to keycloak-admin-client with an initial setup
 */
import KeycloakAdminClient from '@keycloak/keycloak-admin-client'
import type ClientRepresentation from '@keycloak/keycloak-admin-client/lib/defs/clientRepresentation.js'
import { parse } from './helper.js'
import settings from './config.js'
import type { RealmRepresentation } from './types.js'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import type { NodeAppOptions } from '../fixtures/node-console/index.js'
import { NodeApp } from '../fixtures/node-console/index.js'
import type { ConfigInput } from '../../src/middleware/auth-utils/config.js'
import type { AdapterConfig } from '../../src/index.js'
import getToken from './token.js'

const __dirname = fileURLToPath(new URL('.', import.meta.url))

const realmTemplate = join(__dirname, '../fixtures/testrealm.json')

/**
 * Create realms based on port and name specified
 * @param port - The HTTP port which the client app will listen. This is necessary
 * to provide the proper redirect URIs
 * @param name - Realm name
 * @returns A promise that will resolve with the realm object.
 */
export async function createRealm (adminClient: KeycloakAdminClient, name: string): Promise<RealmRepresentation> {
  adminClient.setConfig({ realmName: 'master' })
  await adminClient.auth({ ...settings, grantType: 'password', clientId: 'admin-cli' })
  await adminClient.realms.create(parse(realmTemplate, name))
  const realm = await adminClient.realms.findOne({ realm: name })
  if (realm === undefined) {
    throw new Error('Can\'t find created realm')
  }
  return realm
}

/**
 * Create clients based the representation and name provided
 * @param clientRep - Representation of a client
 * @param name - client name
 */
export async function createClient<C extends ClientRepresentation> (adminClient: KeycloakAdminClient, clientRep: C, realm: string): Promise<ConfigInput> {
  adminClient.setConfig({ realmName: 'master' })
  await adminClient.auth({ ...settings, grantType: 'password', clientId: 'admin-cli' })
  adminClient.setConfig({ realmName: realm })
  const rep = await adminClient.clients.create(clientRep)
  return await adminClient.clients.getInstallationProviders({
    id: rep.id,
    providerId: 'keycloak-oidc-keycloak-json'
  }) as ConfigInput
}

/**
 * Remove the realm based on the name provided
 * @param realm - Realm name
 */
export async function destroy (adminClient: KeycloakAdminClient, realm: string): Promise<void> {
  adminClient.setConfig({ realmName: 'master' })
  await adminClient.auth({ ...settings, grantType: 'password', clientId: 'admin-cli' })
  await adminClient.realms.del({ realm })
}

export interface SetupOptions {
  realmName?: string,
  client?: (app: NodeApp) => ConfigInput,
  config?: (config: ConfigInput) => ConfigInput | void
  app?: NodeAppOptions
  adapterConfig?: AdapterConfig
}

export async function setup (options?: SetupOptions) {
  const realmName = options?.realmName ?? 'test-realm'

  const workerId = process.env.JEST_WORKER_ID
  const effectiveRealmName = `${realmName}-${workerId}`

  const adminClient = new KeycloakAdminClient(settings)
  try {
    await destroy(adminClient, effectiveRealmName)
  } catch {
    // Do nothing
  }

  const app = new NodeApp(options?.app)
  const client = options?.client ?? ((app: NodeApp) => app.publicClient())

  const realm = await createRealm(adminClient, effectiveRealmName)
  let config = await createClient(adminClient, client(app), effectiveRealmName)
  if (options?.config) {
    const alteredConfig = options.config(config)
    if (alteredConfig) {
      config = alteredConfig
    }
  }
  app.build(config, options?.adapterConfig)

  const dispose = async () => {
    try {
      app.destroy()
    } catch {
      // Ignore errors in dispose
    }
    try {
      await destroy(adminClient, effectiveRealmName)
    } catch {
      // Ignore errors in dispose
    }
  }

  return { app, config, adminClient, realm, dispose, getToken: getToken.bind(undefined, realm.realm) }
}
