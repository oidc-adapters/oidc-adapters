/**
 * @group selenium
 */
/* eslint-disable unicorn/no-await-expression-member */
import { ConsolePage, createDriver, RealmAccountPage } from './utils/webdriver.js'
import { setup } from './utils/realm.js'
import { setTimeout } from 'node:timers/promises'
import { MemoryStore } from 'express-session'
import { TestVector } from './utils/helper.js'
import type { ThenableWebDriver } from 'selenium-webdriver'
import { jest } from '@jest/globals'
import settings from './utils/config.js'

jest.setTimeout(20_000)

describe('Using default environment', () => {
  let environment: Awaited<ReturnType<typeof setup>>
  let driver: ThenableWebDriver
  let page: ConsolePage
  let realmAccountPage: RealmAccountPage

  beforeAll(async () => {
    environment = await setup()
  })

  beforeEach(async () => {
    driver = createDriver()
    page = new ConsolePage(driver)
    realmAccountPage = new RealmAccountPage(driver)
  })

  afterEach(async () => {
    await page.quit()
  })

  afterAll(async () => {
    await environment.dispose()
  })

  it('Should be able to access public page', async () => {
    await page.get(environment.app.port)
    const text = await (await page.output()).getText()
    expect(text).toEqual('Init Success (Not Authenticated)')
  })

  it('Should login with admin credentials', async () => {
    await page.get(environment.app.port)
    let text = await (await page.output()).getText()
    expect(text).toEqual('Init Success (Not Authenticated)')
    await (await page.logInButton()).click()
    await page.login('test-admin', 'password')
    text = await (await page.events()).getText()
    expect(text).toEqual('Auth Success')
    await (await page.logOutButton()).click()
    text = await (await page.output()).getText()
    expect(text).toEqual('Init Success (Not Authenticated)')
  })

  it('Login should not change tokens when they are valid', async () => {
    await page.get(environment.app.port)
    await (await page.logInButton()).click()
    await page.login('test-admin', 'password')
    const authSuccessText = await (await page.events()).getText()
    expect(authSuccessText).toEqual('Auth Success')
    const firstToken = await (await page.output()).getText()
    await (await (page.logInButton())).click()
    const secondToken = await (await page.output()).getText()
    // Invoke login for the second time, token shouldn't be changed
    expect(secondToken).toEqual(firstToken)
    await (await (page.logOutButton())).click()
    const initSuccessText = await (await page.output()).getText()
    expect(initSuccessText).toEqual('Init Success (Not Authenticated)')
  })

  it('SSO should work for nodejs app and testRealmAccountPage', async () => {
    await page.get(environment.app.port)
    await (await page.logInButton()).click()
    await page.login('test-admin', 'password')
    const authSuccessText = await (await page.events()).getText()
    expect(authSuccessText).toEqual('Auth Success')
    await realmAccountPage.get()
    let currentUrl = await driver.getCurrentUrl()
    expect(currentUrl).toEqual(realmAccountPage.getUrl())
    await setTimeout(500)
    await realmAccountPage.logout()
    await realmAccountPage.signin()
    currentUrl = await driver.getCurrentUrl()
    expect(currentUrl.startsWith(`${settings.baseUrl}/realms/test-realm/protocol/openid-connect/auth`)).toBeTruthy()
    await page.get(environment.app.port, '/login')
    currentUrl = await driver.getCurrentUrl()
    expect(currentUrl.startsWith(`${settings.baseUrl}/realms/test-realm/protocol/openid-connect/auth`)).toBeTruthy()
  })

  it('User should be forbidden to access restricted page', async () => {
    await page.get(environment.app.port, '/restricted')
    await page.login('alice', 'password')
    const text = await (await page.body()).getText()
    expect(text).toEqual('Access denied')
    await page.logout(environment.app.port)
  })

  it('Should test check SSO after logging in and logging out', async () => {
    // make sure user is logged out
    await page.get(environment.app.port, '/check-sso')
    const checkSsoText1 = await (await page.output()).getText()
    expect(checkSsoText1).toEqual('Check SSO Success (Not Authenticated)')
    await (await (page.logInButton())).click()
    await page.login('alice', 'password')
    await page.get(environment.app.port, '/check-sso')
    const checkSsoText2 = await (await (page.output())).getText()
    expect(checkSsoText2).toEqual('Check SSO Success (Authenticated)')
    await page.logout(environment.app.port)
    await page.get(environment.app.port, '/check-sso')
    const checkSsoText3 = await (await page.output()).getText()
    expect(checkSsoText3).toEqual('Check SSO Success (Not Authenticated)')
  })
})

describe('Using custom environments', () => {
  let driver: ThenableWebDriver
  let page: ConsolePage

  beforeEach(async () => {
    driver = createDriver()
    page = new ConsolePage(driver)
  })

  afterEach(async () => {
    await page.quit()
  })

  it('Public client should be redirected to GitHub when idpHint is provided', async () => {
    const environment = await setup({
      client: (app) => app.publicClient('appIdP'),
      adapterConfig: { store: new MemoryStore(), idpHint: 'github' }
    })

    try {
      await page.get(environment.app.port, '/restricted')
      const text = await (await page.h1()).getText()
      expect(text).toEqual('Sign in to GitHub')
    } finally {
      await environment.dispose()
    }
  })

  it('Public client should be forbidden for invalid public key', async () => {
    const environment = await setup({
      client: (app) => app.publicClient('app2'),
      config: (config) => {
        config['realm-public-key'] = TestVector.wrongRealmPublicKey
      }
    })

    try {
      await page.get(environment.app.port)
      const initSuccessText = await (await page.output()).getText()
      expect(initSuccessText).toEqual('Init Success (Not Authenticated)')
      await (await page.logInButton()).click()
      await page.login('test-admin', 'password')
      const accessDeniedText = await (await page.body()).getText()
      expect(accessDeniedText).toEqual('Access denied')
    } finally {
      await environment.dispose()
    }
  })

  it('Confidential client should be forbidden for invalid public key', async () => {
    const environment = await setup({
      client: (app) => app.confidential('app3'),
      config: (config) => {
        config['realm-public-key'] = TestVector.wrongRealmPublicKey
      }
    })

    try {
      await page.get(environment.app.port)
      const initSuccessText = await (await page.output()).getText()
      expect(initSuccessText).toEqual('Init Success (Not Authenticated)')
      await (await page.logInButton()).click()
      await page.login('test-admin', 'password')
      const accessDeniedText = await (await (page.body())).getText()
      expect(accessDeniedText).toEqual('Access denied')
      await page.logout(environment.app.port)
      await page.logoutConfirm()
      await page.get(environment.app.port, '/check-sso')
      const checkSsoText = await (await page.output()).getText()
      expect(checkSsoText).toEqual('Check SSO Success (Not Authenticated)')
    } finally {
      await environment.dispose()
    }
  })

  it('Public client should work with slash in the end of auth-server-url', async () => {
    const environment = await setup({
      client: (app) => app.publicClient('authServerSlashes'),
      config: (config) => {
        config['auth-server-url'] = 'http://localhost:8080/'
      }
    })

    try {
      await page.get(environment.app.port)
      const initSuccessText = await (await page.output()).getText()
      expect(initSuccessText).toEqual('Init Success (Not Authenticated)')
      await (await page.logInButton()).click()
      await page.login('test-admin', 'password')
      const authSuccessText = await (await page.events()).getText()
      expect(authSuccessText).toEqual('Auth Success')
      await (await page.logOutButton()).click()
      const notAuthenticatedText = await (await page.output()).getText()
      expect(notAuthenticatedText).toEqual('Init Success (Not Authenticated)')
    } finally {
      await environment.dispose()
    }
  })

  it('App should be able to use cookie-store', async () => {
    const environment = await setup({
      client: (app) => app.publicClient('appCookies'),
      adapterConfig: { cookies: true }
    })

    try {
      await page.get(environment.app.port, '/cookie')
      await page.login('alice', 'password')
      const firstText = await (await page.events()).getText()
      expect(firstText).toEqual('Keycloak token is set in cookies')
      await driver.navigate().refresh()
      const secondText = await (await page.events()).getText()
      expect(secondText).toEqual('Keycloak token is set in cookies')
    } finally {
      await environment.dispose()
    }
  })

  it('App should not use cookie-store when not configured', async () => {
    const environment = await setup({
      client: (app) => app.publicClient('appCookies')
    })

    try {
      await page.get(environment.app.port, '/cookie')
      await page.login('alice', 'password')
      const firstText = await (await page.events()).getText()
      expect(firstText).toEqual('Keycloak token is NOT set in cookies')
    } finally {
      await environment.dispose()
    }
  })
})
