import path from 'node:path'
import fs from 'node:fs'

export interface ConfigInput {
  realm?: string
  resource?: string
  clientId?: string
  ['client-id']?: string
  secret?: string,
  credentials?: {
    secret?: string
  }
  public?: boolean
  ['public-client']?: boolean
  authServerUrl?: string
  ['auth-server-url']?: string
  serverUrl?: string
  ['server-url']?: string
  minTimeBetweenJwksRequests?: number
  ['min-time-between-jwks-requests']?: number
  bearerOnly?: boolean,
  ['bearer-only']?: boolean
  realmPublicKey?: string
  ['realm-public-key']?: string
  verifyTokenAudience?: boolean
  ['verify-token-audience']?: boolean
}

const isUrl = (o: unknown): o is URL => {
  if ((o as URL).protocol) {
    return true
  }
  return false
}

export default class Config {
  /**
   * Realm ID
   */
  realm!: string

  /**
   * Client/Application ID
   */
  clientId?: string

  /**
   * Client/Application secret
   */
  secret?: string

  /**
   * If this is a public application or confidential.
   */
  public!: boolean

  /**
   * Authentication server URL
   */
  authServerUrl?: string

  /**
   * Root realm URL.
   */
  realmUrl!: string

  /**
   * Root realm admin URL.
   */
  realmAdminUrl!: string

  /**
   * How many minutes before retrying getting the keys.
   */
  minTimeBetweenJwksRequests!: number

  /**
   * If this is a Bearer Only application.
   */
  bearerOnly!: boolean

  /**
   * Formatted public-key.
   */
  publicKey?: string

  /**
   * Verify token audience
   */
  verifyTokenAudience!: boolean

  /**
   * Construct a configuration object.
   *
   * A configuration object may be constructed with either
   * a path to a `keycloak.json` file (which defaults to
   * `$PWD/keycloak.json` if not present, or with a configuration
   * object akin to what parsing `keycloak.json` provides.
   *
   * @param {String|Object} config Configuration path or details.
   *
   * @constructor
   */
  constructor (config?: fs.PathOrFileDescriptor | ConfigInput) {
    if (!config) {
      config = path.join(process.cwd(), 'keycloak.json')
    }

    if (typeof config === 'string' || typeof config === 'number' || config instanceof Buffer || isUrl(config)) {
      this.loadConfiguration(config)
    } else {
      this.configure(config)
    }
  }

  /**
   * Load configuration from a path.
   *
   * @param {String} configPath Path to a `keycloak.json` configuration.
   */
  loadConfiguration (configPath: fs.PathOrFileDescriptor) {
    const json = fs.readFileSync(configPath)
    const config = JSON.parse(json.toString()) as ConfigInput
    this.configure(config)
  }

  private resolveValue (value: string): string
  private resolveValue<T> (value: T): T
  private resolveValue<T> (value: string | T): T | string {
    if (typeof value !== 'string') {
      return value
    }

    // "${env.MY_ENVIRONMENT_VARIABLE:http://localhost:8080}".replace(/\$\{env\.([^:]*):?(.*)?\}/,"$1--split--$2").split("--split--")
    // eslint-disable-next-line unicorn/better-regex
    const regex = /\$\{env\.([^:]*):?(.*)?\}/

    // is this an environment variable reference with potential fallback?
    if (!regex.test(value)) {
      return value
    }

    const tokens = value.replace(regex, '$1--split--$2').split('--split--')
    const environmentVariable = tokens[0]
    const environmentValue = process.env[environmentVariable]
    const fallbackValue = tokens[1]

    return environmentValue ?? fallbackValue
  }

  /**
   * Tries to resolve environment variables in the given value in case it is of type "string", else the given value is returned.
   * Environment variable references look like: '${env.MY_ENVIRONMENT_VARIABLE}', optionally one can configure a fallback
   * if the referenced env variable is not present. E.g. '${env.NOT_SET:http://localhost:8080}' yields 'http://localhost:8080'.
   */
  configure (config: ConfigInput): void {
    this.realm = this.resolveValue(config.realm) ?? 'master'
    this.clientId = this.resolveValue(config.resource ?? config['client-id'] ?? config.clientId)
    this.secret = this.resolveValue((config.credentials ?? {}).secret ?? config.secret)
    this.public = this.resolveValue(config['public-client'] ?? config.public ?? false)
    this.authServerUrl = (this.resolveValue(config['auth-server-url'] ?? config['server-url'] ?? config.serverUrl ?? config.authServerUrl) ?? '').replace(/\/*$/gi, '')
    this.realmUrl = `${this.authServerUrl}/realms/${this.realm}`
    this.realmAdminUrl = `${this.authServerUrl}/admin/realms/${this.realm}`
    this.minTimeBetweenJwksRequests = config['min-time-between-jwks-requests'] ?? config.minTimeBetweenJwksRequests ?? 10
    this.bearerOnly = this.resolveValue(config['bearer-only'] ?? config.bearerOnly ?? false)

    const plainKey = this.resolveValue(config['realm-public-key'] ?? config.realmPublicKey)

    if (plainKey) {
      let publicKey = '-----BEGIN PUBLIC KEY-----\n'
      for (let index = 0; index < plainKey.length; index = index + 64) {
        publicKey += plainKey.slice(index, index + 64)
        publicKey += '\n'
      }
      publicKey += '-----END PUBLIC KEY-----\n'
      this.publicKey = publicKey
    }

    this.verifyTokenAudience = this.resolveValue(config['verify-token-audience'] ?? config.verifyTokenAudience ?? false)
  }
}
