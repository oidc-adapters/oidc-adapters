import Rotation from './rotation.js'
import type Config from './config.js'
import crypto from 'node:crypto'
import type Token from './token.js'

export default class Signature {
  private publicKey: string | undefined
  private rotation: Rotation

  /**
   * Construct a signature.
   *
   * @param {Config} config Config object.
   *
   * @constructor
   */
  constructor (config: Config) {
    this.publicKey = config.publicKey
    this.rotation = new Rotation(config)
  }

  /**
   * Verify signed data using the token information provided
   * @TODO in the future provide more alternatives like HS256 support
   * @param token Token object
   */
  async verify (token: Token) {
    const verify = crypto.createVerify('RSA-SHA256')

    if (!token.header?.kid) {
      throw new Error('failed to load public key to verify token. Reason: kid is missing')
    }

    if (!token.signed) {
      throw new Error('failed to load public key to verify token. Reason: signed is missing')
    }

    if (!token.signature) {
      throw new Error('failed to load public key to verify token. Reason: signature is missing')
    }

    const key = await this.rotation.getJWK(token.header.kid)
    if (!key) {
      throw new Error('Can\t retrieve key after rotation')
    }

    verify.update(token.signed)
    if (!verify.verify(key, token.signature)) {
      throw new Error('admin request failed: invalid token (signature)')
    }

    return token
  }
}
