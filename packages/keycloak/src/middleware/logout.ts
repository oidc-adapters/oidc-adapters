import URL from 'node:url'
import type Keycloak from '../keycloak.js'
import type { NextFunction, Request, Response } from 'express'

export default function (keycloak: Keycloak, logoutUrl: string) {
  return function logout (request: Request, response: Response, next: NextFunction) {
    const parsedRequest = URL.parse(request.url, true)
    if (parsedRequest.pathname !== logoutUrl) {
      return next()
    }

    let idTokenHint: string | undefined
    if (request.kauth?.grant) {
      idTokenHint = request.kauth.grant.id_token?.token
      keycloak.deauthenticated(request)
      request.kauth.grant.unstore?.(request, response)
      delete request.kauth.grant
    }

    const queryParameters = parsedRequest.query
    let redirectUrl = Array.isArray(queryParameters.redirect_url) ? queryParameters.redirect_url[0] : queryParameters.redirect_url
    if (!redirectUrl) {
      const host = request.hostname
      const portNumber = request.headers.host?.split(':')[1] ?? ''
      const port = (!portNumber || portNumber.length === 0) ? '' : `:${portNumber}`
      redirectUrl = `${request.protocol}://${host}${port}/`
    }
    const keycloakLogoutUrl = keycloak.logoutUrl(redirectUrl, idTokenHint)

    response.redirect(keycloakLogoutUrl)
  }
}
