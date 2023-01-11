import Token from './auth-utils/token.js'
import Signature from './auth-utils/signature.js'
import type Keycloak from '../index.js'
import type { NextFunction, Request, Response } from 'express'

function adminLogout (request: Request, response: Response, keycloak: Keycloak) {
  let data = ''

  request.on('data', (d: Buffer) => {
    data += d.toString()
  })

  request.on('end', function () {
    const token = new Token(data)
    let signature
    try {
      signature = new Signature(keycloak.config)
      signature.verify(token).then(token => {
        if (token.content.action === 'LOGOUT') {
          const sessionIDs = token.content.adapterSessionIds
          if (!sessionIDs) {
            keycloak.grantManager.notBefore = token.content.notBefore
            response.send('ok')
            return
          }
          if (sessionIDs && sessionIDs.length > 0) {
            let seen = 0
            for (const id of sessionIDs) {
              // eslint-disable-next-line @typescript-eslint/no-floating-promises
              keycloak.unstoreGrant(id)
              ++seen
              if (seen === sessionIDs.length) {
                response.send('ok')
              }
            }
          } else {
            response.send('ok')
          }
        } else {
          response.status(400).end()
        }

        return token
      }).catch((error) => {
        response.status(401).end((error as Error).message)
      })
    } catch (error) {
      response.status(400).end((error as Error).message)
    }
  })
}

function adminNotBefore (request: Request, response: Response, keycloak: Keycloak) {
  let data = ''
  request.on('data', (d: Buffer) => {
    data += d.toString()
  })

  request.on('end', function () {
    const token = new Token(data)
    let signature
    try {
      signature = new Signature(keycloak.config)
      signature.verify(token).then(token => {
        if (token.content.action === 'PUSH_NOT_BEFORE') {
          keycloak.grantManager.notBefore = token.content.notBefore
          response.send('ok')
        }

        return token
      }).catch((error: unknown) => {
        response.status(401).end((error as Error).message)
      })
    } catch (error: unknown) {
      response.status(400).end((error as Error).message)
    }
  })
}

export default function (keycloak: Keycloak, adminUrl: string) {
  let url = adminUrl
  if (url[url.length - 1] !== '/') {
    url = url + '/'
  }
  const urlLogout = url + 'k_logout'
  const urlNotBefore = url + 'k_push_not_before'

  return function adminRequest (request: Request, response: Response, next: NextFunction) {
    switch (request.url) {
      case urlLogout: {
        adminLogout(request, response, keycloak)
        break
      }
      case urlNotBefore: {
        adminNotBefore(request, response, keycloak)
        break
      }
      default: {
        return next()
      }
    }
  }
}
