import { v4 as UUID } from 'uuid'
import URL from 'node:url'
import type Keycloak from '../index.js'
import type { NextFunction, Request, Response } from 'express'

function forceCheckSSO (keycloak: Keycloak, request: Request, response: Response) {
  const host = request.hostname
  const port = request.headers.host?.split(':')?.[1] ?? ''
  const protocol = request.protocol
  const hasQuery = ~(request.originalUrl || request.url).indexOf('?')

  const redirectUrl = protocol + '://' + host + (port === '' ? '' : ':' + port) + (request.originalUrl || request.url) + (hasQuery ? '&' : '?') + 'auth_callback=1'

  if (request.session) {
    request.session.auth_redirect_uri = redirectUrl
  }

  const uuid = UUID().toString()
  const loginURL = keycloak.loginUrl(uuid, redirectUrl)
  const checkSsoUrl = loginURL + '&response_mode=query&prompt=none'

  response.redirect(checkSsoUrl)
}

export default function (keycloak: Keycloak) {
  return function checkSso (request: Request, response: Response, next: NextFunction) {
    if (request.kauth && request.kauth.grant) {
      return next()
    }

    //  Check SSO process is completed and user is not logged in
    if (request.session.auth_is_check_sso_complete) {
      request.session.auth_is_check_sso_complete = false
      return next()
    }

    //  Keycloak server has just answered that user is not logged in
    if (request.query.error === 'login_required') {
      const urlParts = {
        pathname: request.path,
        query: request.query
      }

      delete urlParts.query.error
      delete urlParts.query.auth_callback
      delete urlParts.query.state

      // TODO: Remove this deprecated method
      const cleanUrl = URL.format(urlParts as unknown as URL)

      //  Check SSO process is completed
      request.session.auth_is_check_sso_complete = true

      //  Redirect back to the original URL
      return response.redirect(cleanUrl)
    }

    if (keycloak.redirectToLogin(request)) {
      forceCheckSSO(keycloak, request, response)
    } else {
      return keycloak.accessDenied(request, response)
    }
  }
}
