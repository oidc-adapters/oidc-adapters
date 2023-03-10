/* eslint-disable jest/no-standalone-expect */
import { Strategy } from '../src/strategy.js'
import passport from 'passport'
import type { Express } from 'express'
import express from 'express'
import request from 'supertest'
import { DirectGrant } from '@oidc-adapters/core'
import jwtDecode from 'jwt-decode'

describe('strategy.ts', function () {
  let app: Express
  let server: ReturnType<Express['listen']>

  beforeAll(() => {
    app = express()
    server = app.listen()

    const oidcStrategy = new Strategy({ allowedIssuers: ['http://localhost:8109/realms/master'] })
    passport.use(oidcStrategy)

    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    app.get('/', passport.authenticate('oidc', { session: false }), (request, response) => {
      expect(request.user).toBeDefined()
      const jwtPayload = request.user?.jwtPayload
      const jwt = request.user?.jwt

      expect(jwtPayload).toBeDefined()
      expect(jwt).toBeDefined()
      const decodedJwt = jwtDecode(jwt!)
      expect(jwtPayload).toEqual(decodedJwt)

      response.status(200).json({})
    })
  })

  afterAll(() => {
    server.close()
  })

  it('should deny access to unauthenticated user', async () => {
    await request(app).get('/').expect(401)
  })

  it('should allow access to authenticated user', async () => {
    const directGrant = new DirectGrant({
      authority: 'http://localhost:8109/realms/master',
      client_id: 'admin-cli'
    })

    const tokenReponseJson = await directGrant.password('admin', 'admin')

    await request(app).get('/').set('Authorization', `bearer ${tokenReponseJson.access_token}`).expect(200)
  })
})
