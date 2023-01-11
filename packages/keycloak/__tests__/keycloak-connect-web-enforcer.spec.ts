/**
 * @group selenium
 */
/* eslint-disable unicorn/no-await-expression-member */
import { ConsolePage, createDriver } from './utils/webdriver.js'
import { setup } from './utils/realm.js'
import type { ThenableWebDriver } from 'selenium-webdriver'
import { jest } from '@jest/globals'

jest.setTimeout(20_000)

describe('Using default environment', () => {
  let environment: Awaited<ReturnType<typeof setup>>
  let driver: ThenableWebDriver
  let page: ConsolePage

  beforeAll(async () => {
    environment = await setup({ client: (app) => app.enforcerResourceServer() })
  })

  beforeEach(async () => {
    driver = createDriver()
    page = new ConsolePage(driver)
  })

  afterEach(async () => {
    await page.quit()
  })

  afterAll(async () => {
    await environment.dispose()
  })

  test('Should be able to access resource protected by the policy enforcer', async () => {
    await page.get(environment.app.port)

    const initSuccessText = await (await page.output()).getText()
    expect(initSuccessText).toEqual('Init Success (Not Authenticated)')
    await (await page.logInButton()).click()
    await page.login('test-admin', 'password')

    const authSuccessText = await (await page.events()).getText()
    expect(authSuccessText).toEqual('Auth Success')

    await (await (page.grantedResourceButton())).click()
    const grantedText = await (await page.events()).getText()
    expect(grantedText).toEqual('Granted')
  })
})
