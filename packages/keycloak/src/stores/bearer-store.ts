import type { Request } from 'express'
import type { Store } from './index.js'

export default class BearerStore implements Store {
  get (request: Request) {
    const header = request.headers.authorization

    if (header && (header.indexOf('bearer ') === 0 || header.indexOf('Bearer ') === 0)) {
      const accessToken = header.slice(7)
      return {
        access_token: accessToken
      }
    }
  }
}
