/* eslint-disable @typescript-eslint/no-misused-promises */
import type { AdapterConfig } from '../../../src/index.js'
import Keycloak from '../../../src/index.js'
import bodyParser from 'body-parser'
import mustacheExpress from 'mustache-express'
import type { Express, Request, Response } from 'express'
import express from 'express'
import session, { MemoryStore } from 'express-session'
import cookieParser from 'cookie-parser'
import enableDestroy from 'server-destroy'
import { parseClient } from '../../utils/helper.js'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import type { PathOrFileDescriptor } from 'node:fs'
import type { ConfigInput } from '../../../src/middleware/auth-utils/config.js'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

const __dirname = fileURLToPath(new URL('.', import.meta.url))

class KeycloakTest extends Keycloak {
  redirectToLogin (request: Request): boolean {
    const apiMatcher = /^\/service\/.*/i
    return !apiMatcher.test(request.url)
  }
}

export interface NodeAppOptions {port?: number}

export class NodeApp {
  app: Express
  port: number
  address: string
  server: Server

  constructor (options?: NodeAppOptions) {
    this.app = express()
    this.app.use(cookieParser())
    this.server = this.app.listen(options?.port ?? 0)
    enableDestroy(this.server)

    this.port = (this.server.address() as AddressInfo).port
    this.address = `http://localhost:${this.port}`

    // console.log('Testing app listening at http://localhost:%s', this.port)
  }

  close () {
    this.server.close()
  }

  destroy () {
    this.server.destroy()
  }

  publicClient (name = 'public-app') {
    return parseClient(join(__dirname, '../templates/public-template.json'), `${this.port}`, name)
  }

  bearerOnly (name = 'bearer-app') {
    return parseClient(join(__dirname, '../templates/bearerOnly-template.json'), `${this.port}`, name)
  }

  confidential (name = 'confidential-app') {
    return parseClient(join(__dirname, '../templates/confidential-template.json'), `${this.port}`, name)
  }

  enforcerResourceServer (name = 'resource-server-app') {
    return parseClient(join(__dirname, '../templates/resource-server-template.json'), `${this.port}`, name)
  }

  build (keycloakConfig: PathOrFileDescriptor | ConfigInput, adapterConfig?: AdapterConfig) {
    this.app.set('view engine', 'html')
    this.app.set('views', join(__dirname, '/views'))
    this.app.engine('html', mustacheExpress())

    // Create a session-store to be used by both the express-session
    // middleware and the keycloak middleware.

    const memoryStore = new MemoryStore()

    this.app.use(session({
      secret: 'mySecret',
      resave: false,
      saveUninitialized: true,
      store: memoryStore
    }))

    // Provide the session store to the Keycloak so that sessions
    // can be invalidated from the Keycloak console callback.
    //
    // Additional configuration is read from keycloak.json file
    // installed from the Keycloak web console.
    adapterConfig = adapterConfig ?? { store: memoryStore }
    const keycloak = new KeycloakTest(adapterConfig, keycloakConfig)

    // A normal un-protected public URL.
    this.app.get('/', (request, response) => {
      const authenticated = 'Init Success (' + (request.session['keycloak-token'] ? 'Authenticated' : 'Not Authenticated') + ')'
      output(response, authenticated)
    })

    // Install the Keycloak middleware.
    //
    // Specifies that the user-accessible application URL to
    // logout should be mounted at /logout
    //
    // Specifies that Keycloak console callbacks should target the
    // root URL.  Various permutations, such as /k_logout will ultimately
    // be appended to the admin URL.

    this.app.use(keycloak.middleware({
      logout: '/logout',
      admin: '/'
    }))

    this.app.get('/login', keycloak.protect(), (request, response) => {
      let keycloakToken = request.session['keycloak-token']
      if (keycloakToken) {
        keycloakToken = JSON.stringify(JSON.parse(keycloakToken), undefined, 4)
      }
      output(response, keycloakToken, 'Auth Success')
    })

    this.app.get('/check-sso', keycloak.checkSso(), (request, response) => {
      const authenticated = 'Check SSO Success (' + (request.session['keycloak-token'] ? 'Authenticated' : 'Not Authenticated') + ')'
      output(response, authenticated)
    })

    this.app.get('/restricted', keycloak.protect('realm:admin'), (request, response) => {
      const user = request.kauth?.grant?.access_token?.content.preferred_username
      output(response, user, 'Restricted access')
    })

    this.app.get('/cookie', keycloak.protect(), (request: Request, response: Response) => {
      let authenticated = 'Keycloak token is NOT set in cookies'
      let keycloakToken = request.cookies['keycloak-token']
      if (keycloakToken) {
        authenticated = 'Keycloak token is set in cookies'
        keycloakToken = JSON.stringify(JSON.parse(keycloakToken), undefined, 4)
      }
      output(response, keycloakToken, authenticated)
    })

    this.app.get('/service/public', (request, response) => {
      response.json({ message: 'public' })
    })

    this.app.get('/service/secured', keycloak.protect('realm:user'), (request, response) => {
      response.json({ message: 'secured' })
    })

    this.app.get('/service/admin', keycloak.protect('realm:admin'), (request, response) => {
      response.json({ message: 'admin' })
    })

    this.app.get('/service/grant', keycloak.protect(), async (request, response, next) => {
      try {
        const grant = await keycloak.getGrant(request, response)
        response.json(grant)
      } catch (error) {
        next(error)
      }
    })

    this.app.post('/service/grant', bodyParser.json(), async (request, response, next) => {
      const username = request.body.username as string | undefined
      const password = request.body.password as string | undefined

      if (username === undefined || password === undefined) {
        response.status(400).send('Username and password required')
        return
      }

      try {
        const grant = await keycloak.grantManager.obtainDirectly(username, password)
        keycloak.storeGrant(grant, request, response)
        response.json(grant)
      } catch (error) {
        next(error)
      }
    })

    this.app.get('/protected/enforcer/resource', keycloak.enforcer('resource:view'), (request, response) => {
      response.json({ message: 'resource:view', permissions: request.permissions })
    })

    this.app.post('/protected/enforcer/resource', keycloak.enforcer('resource:update'), (request, response) => {
      response.json({ message: 'resource:update', permissions: request.permissions })
    })

    this.app.delete('/protected/enforcer/resource', keycloak.enforcer('resource:delete'), (request, response) => {
      response.json({ message: 'resource:delete', permissions: request.permissions })
    })

    this.app.get('/protected/enforcer/resource-view-delete', keycloak.enforcer(['resource:view', 'resource:delete']), (request, response) => {
      response.json({ message: 'resource:delete', permissions: request.permissions })
    })

    this.app.get('/protected/enforcer/resource-claims', keycloak.enforcer(['photo'], {
      claims: (request) => {
        return {
          user_agent: [request.query.user_agent]
        }
      }
    }), (request, response) => {
      response.json({ message: request.query.user_agent, permissions: request.permissions })
    })

    this.app.get('/protected/enforcer/no-permission-defined', keycloak.enforcer(), (request, response) => {
      response.json({ message: 'always grant', permissions: request.permissions })
    })

    this.app.get('/protected/web/resource', keycloak.enforcer(['resource:view']), (request, response) => {
      const user = request.kauth?.grant?.access_token?.content.preferred_username
      output(response, user, 'Granted')
    })

    this.app.use('*', (request, response) => {
      response.send('Not found!')
    })
  }
}

function output (response: Response, output?: string, eventMessage?: string, page = 'index') {
  response.render(page, {
    result: output,
    event: eventMessage
  })
}
