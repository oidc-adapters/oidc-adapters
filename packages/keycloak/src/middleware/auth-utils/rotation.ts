import URL from 'node:url'
import type https from 'node:https'
import type { JWK } from 'jwk-to-pem'
import jwkToPem from 'jwk-to-pem'
import type Config from './config.js'
import { getProtocol } from '../utils.js'

export interface Jwks {
  error?: unknown
  keys: Jwk[]
}

export type Jwk = JWK & { kid?: string }

export default class Rotation {
  private realmUrl: string
  private minTimeBetweenJwksRequests: number
  private jwks: Jwk[]
  private lastTimeRequesTime: number

  /**
   * Construct a Rotation instance
   *
   * @param {Config} config Config object.
   *
   * @constructor
   */
  constructor (config: Config) {
    this.realmUrl = config.realmUrl
    this.minTimeBetweenJwksRequests = config.minTimeBetweenJwksRequests
    this.jwks = []
    this.lastTimeRequesTime = 0
  }

  async retrieveJWKs (): Promise<Jwks> {
    const url = this.realmUrl + '/protocol/openid-connect/certs'
    const options: https.RequestOptions = URL.parse(url)
    options.method = 'GET'
    const promise = new Promise<Jwks>((resolve, reject) => {
      const request = getProtocol(options).request(options, (response) => {
        if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
          return reject(new Error('Error fetching JWK Keys'))
        }
        let json = ''
        response.on('data', (d: Buffer) => (json += d.toString()))
        response.on('end', () => {
          const data = JSON.parse(json) as Jwks
          if (data.error) reject(data)
          else resolve(data)
        })
      })
      request.on('error', reject)
      request.end()
    })
    return promise
  }

  async getJWK (kid: string): Promise<string | undefined> {
    const key = this.jwks.find((key) => { return key.kid === kid })
    if (key) {
      return jwkToPem(key)
    }

    // check if we are allowed to send request
    const currentTime = Date.now() / 1000
    if (currentTime > this.lastTimeRequesTime + this.minTimeBetweenJwksRequests) {
      const publicKeys = await this.retrieveJWKs()
      this.lastTimeRequesTime = currentTime
      this.jwks = publicKeys.keys
      const newKey = this.jwks.find(key => key.kid === kid)
      if (newKey) {
        return jwkToPem(newKey)
      }
    } else {
      console.error('Not enough time elapsed since the last request, blocking the request')
    }
  }

  clearCache () {
    this.jwks.length = 0
  }
}
