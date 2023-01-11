import { v4 as UUID } from 'uuid'

import type Keycloak from '../index.js'
import type { NextFunction, Request, Response } from 'express'
import type Token from './auth-utils/token.js'

export type ProtectSpec = string | ((token: Token, request: Request, response: Response) => boolean)

function forceLogin (keycloak: Keycloak, request: Request, response: Response) {
  const host = request.hostname
  const port = request.headers.host?.split(':')?.[1] ?? ''
  const protocol = request.protocol
  const hasQuery = ~(request.originalUrl || request.url).indexOf('?')

  const redirectUrl = protocol + '://' + host + (port === '' ? '' : ':' + port) + (request.originalUrl || request.url) + (hasQuery ? '&' : '?') + 'auth_callback=1'

  if (request.session) {
    request.session.auth_redirect_uri = redirectUrl
  }

  const uuid = UUID()
  const loginURL = keycloak.loginUrl(uuid, redirectUrl)
  response.redirect(loginURL)
}

export default function (keycloak: Keycloak, spec?: string | ((token: Token, request: Request, response: Response) => boolean)) {
  let guard: (token: Token, request: Request, response: Response) => boolean | undefined

  if (typeof spec === 'function') {
    guard = spec
  } else if (typeof spec === 'string') {
    guard = (token: Token) => token.hasRole(spec)
  }

  return function protect (request: Request, response: Response, next: NextFunction) {
    const accessToken = request.kauth?.grant?.access_token
    if (accessToken) {
      if (!guard || guard(accessToken, request, response)) {
        return next()
      }

      return keycloak.accessDenied(request, response)
    }

    if (keycloak.redirectToLogin(request)) {
      forceLogin(keycloak, request, response)
    } else {
      return keycloak.accessDenied(request, response)
    }
  }
}
