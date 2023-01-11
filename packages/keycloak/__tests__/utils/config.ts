import type { Credentials } from '@keycloak/keycloak-admin-client/lib/utils/auth.js'

const settings: Partial<Credentials> & { baseUrl: string, realmName: string } = {
  baseUrl: process.env.OIDC_ADAPTERS_KEYCLOAK_TEST_BASE_URL ?? 'http://localhost:8109',
  realmName: process.env.OIDC_ADAPTERS_KEYCLOAK_TEST_REALM_NAME ?? 'master',
  username: process.env.OIDC_ADAPTERS_KEYCLOAK_TEST_USERNAME ?? 'admin',
  password: process.env.OIDC_ADAPTERS_KEYCLOAK_TEST_PASSWORD ?? 'admin'
}

export default settings
