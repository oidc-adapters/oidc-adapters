/**
 * @group integration
 * @group timeout
 */
import { setTimeout } from 'node:timers/promises'
import { buildGrantManager } from './utils/grant.js'

test('GrantManager should be able to refresh token after accessTokenLifespan', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-token-test.json')
  let grant = await manager.obtainDirectly('bburke@redhat.com', 'password')
  const firstToken = await manager.validateAccessToken(grant.access_token!)
  expect(firstToken).not.toBe(false)
  grant = await manager.ensureFreshness(grant)
  expect(grant.access_token).toEqual(firstToken)
  await setTimeout(10_000)
  expect(grant.access_token!.isExpired()).toBe(true)
  grant = await manager.ensureFreshness(grant)
  const refreshedToken = await manager.validateAccessToken(grant.access_token!)
  expect(refreshedToken).not.toBe(false)
  expect(refreshedToken).not.toEqual(firstToken)
}, 15_000)

test('GrantManager should not be able to refresh token after ssoSessionIdleTimeout', async () => {
  const manager = buildGrantManager('./fixtures/auth-utils/keycloak-token-test.json')
  const grant = await manager.obtainDirectly('bburke@redhat.com', 'password')
  const firstToken = await manager.validateAccessToken(grant.access_token!)
  expect(firstToken).not.toBe(false)
  await setTimeout(15_000 + 120_000)// 15 second ssoSessionIdleTimeout + 120s IDLE_TIMEOUT_WINDOW_SECONDS from https://github.com/keycloak/keycloak/blob/master/server-spi-private/src/main/java/org/keycloak/models/utils/SessionTimeoutHelper.java
  await expect(() => manager.ensureFreshness(grant)).rejects.toThrow('Unable to refresh with expired refresh token')
}, 15_000 + 120_000 + 5000)
