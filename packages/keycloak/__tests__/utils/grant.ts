import type { PathOrFileDescriptor } from 'node:fs'
import { readFileSync } from 'node:fs'
import type { ConfigInput } from '../../src/middleware/auth-utils/config.js'
import Config from '../../src/middleware/auth-utils/config.js'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import settings from './config.js'
import GrantManager from '../../src/middleware/auth-utils/grant-manager.js'

export function buildGrantManager (fixture: PathOrFileDescriptor | ConfigInput, options?: { keepServerUrl: boolean }) {
  if (typeof fixture === 'string') {
    const __dirname = fileURLToPath(new URL('..', import.meta.url))
    fixture = join(__dirname, fixture)

    if (options?.keepServerUrl !== true) {
      const configInput = readFileSync(fixture)
      fixture = JSON.parse(configInput.toString('utf8')) as ConfigInput

      // Override authServerUrl with test settings
      if (fixture.authServerUrl) {
        fixture.authServerUrl = settings.baseUrl
      }

      if (fixture['auth-server-url']) {
        fixture['auth-server-url'] = settings.baseUrl
      }

      if (fixture.serverUrl) {
        fixture.serverUrl = settings.baseUrl
      }

      if (fixture['server-url']) {
        fixture['server-url'] = settings.baseUrl
      }
    }
  }

  return new GrantManager(new Config(fixture))
}
