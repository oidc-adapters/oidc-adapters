import type { URL } from 'node:url'
import { format as formatUrl } from 'node:url'

import type Keycloak from '../index.js'
import type { NextFunction, Request, Response } from 'express'

export default function (keycloak: Keycloak) {
  return async function postAuth (request: Request, response: Response, next: NextFunction) {
    if (!request.query.auth_callback) {
      return next()
    }

    //  During the check SSO process the Keycloak server answered the user is not logged in
    if (request.query.error === 'login_required') {
      return next()
    }

    if (request.query.error) {
      return keycloak.accessDenied(request, response)
    }

    if (!request.query.code) {
      return keycloak.accessDenied(request, response)
    }

    if (typeof request.query.code !== 'string') {
      return keycloak.accessDenied(request, response)
    }

    try {
      const grant = await keycloak.getGrantFromCode(request.query.code, request, response)

      const urlParts = {
        pathname: request.path,
        query: request.query
      }

      delete urlParts.query.code
      delete urlParts.query.auth_callback
      delete urlParts.query.state
      delete urlParts.query.session_state

      // TODO: Remove this deprecated method
      const cleanUrl = formatUrl(urlParts as unknown as URL)

      if (request.kauth === undefined) {
        request.kauth = {}
      }
      request.kauth.grant = grant
      try {
        keycloak.authenticated(request)
      } catch (error) {
        console.log(error)
      }
      response.redirect(cleanUrl)
    } catch {
      keycloak.accessDenied(request, response)
    }
  }
}
