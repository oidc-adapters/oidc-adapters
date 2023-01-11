import { Options } from 'selenium-webdriver/chrome'
import type { Locator, ThenableWebDriver, WebElement } from 'selenium-webdriver'
import { Builder, By, until } from 'selenium-webdriver'

import type { ParsedArgs } from 'minimist'
import minimist from 'minimist'
import { setTimeout } from 'node:timers/promises'
import settings from './config.js'

const arguments_ = minimist(process.argv.slice(2))

export function createDriver () {
  const o = new Options()
  o.addArguments('disable-infobars')
  o.addArguments('headless')

  if (arguments_.chromeArguments) {
    const chromeArguments = (arguments_ as ParsedArgs & { chromeArguments: string }).chromeArguments.split(' ')
    console.log(`Using additional chrome arguments [${chromeArguments}]`)
    o.addArguments(...chromeArguments)
  }

  o.setUserPreferences({ credential_enable_service: false })

  return new Builder()
    .setChromeOptions(o)
    .forBrowser('chrome')
    .build()
}

export abstract class AbstractDriverWrapper {
  constructor (protected readonly driver: ThenableWebDriver) {
  }

  /* eslint-disable no-unused-vars */
  async waitForElement (locator: Locator, timeout = 10_000): Promise<WebElement> {
    return this.driver.wait(until.elementLocated(locator), timeout)
  }

  /* eslint-disable no-unused-vars */
  async waitForVisibleElement (locator: Locator, timeout = 10_000) {
    const element = await this.driver.wait(until.elementLocated(locator), timeout)
    return this.driver.wait(until.elementIsVisible(element), timeout)
  }

  async print () {
    const pageSource = await this.driver.getPageSource()
    console.log(pageSource)
  }

  async quit () {
    await this.driver.manage().deleteAllCookies()
    await this.driver.quit()
  }
}

export class ConsolePage extends AbstractDriverWrapper {
  async get (port: number, resource = '') {
    await this.driver.get(`http://localhost:${port}${resource}`)
  }

  async logInButton () {
    return this.driver.findElement(By.xpath('//button[text() = \'Login\']'))
  }

  async output () {
    return this.driver.findElement(By.id('output'))
  }

  async logOutButton () {
    return this.driver.findElement(By.xpath('//button[text() = \'Logout\']'))
  }

  async events () {
    return this.driver.findElement(By.id('events'))
  }

  async grantedResourceButton () {
    return this.driver.findElement(By.xpath('//button[text() = \'Granted Resource\']'))
  }

  async login (user: string, pass: string) {
    const username = await this.waitForVisibleElement(By.id('username'))
    await username.clear()
    await username.sendKeys(user)

    const password = await this.driver.findElement(By.id('password'))
    await password.clear()
    await password.sendKeys(pass)

    const webElement = await this.driver.findElement(By.name('login'))
    await webElement.click()
  }

  /**
   * Logouts directly with support for a wait period
   *
   * @param port
   * @returns {Promise<any>}
   */
  async logout (port: number) {
    await this.get(port, '/logout')
    await setTimeout(2000)
  }

  /**
   * Confirmation of the logout screen
   */
  async logoutConfirm () {
    await this.waitForVisibleElement(By.id('kc-logout'))
    const webElement = await this.driver.findElement(By.id('kc-logout'))
    await webElement.click()
  }

  async body () {
    return this.driver.findElement(By.tagName('pre'))
  }

  async h1 () {
    return this.driver.findElement(By.tagName('h1'))
  }
}

export class RealmAccountPage extends AbstractDriverWrapper {
  constructor (driver: ThenableWebDriver) {
    super(driver)
  }

  get (realm = 'test-realm') {
    return this.driver.get(this.getUrl(realm))
  }

  getUrl (realm = 'test-realm') {
    return `${settings.baseUrl}/realms/${realm}/account/`
  }

  async logout () {
    const webElement = await this.waitForVisibleElement(By.id('landingSignOutButton'))
    await webElement.click()
  }

  async signin () {
    const webElement = await this.waitForVisibleElement(By.id('landingSignInButton'))
    await webElement.click()
  }
}
