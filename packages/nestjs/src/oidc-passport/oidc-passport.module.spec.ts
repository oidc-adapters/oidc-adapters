import { Test } from '@nestjs/testing'
import { OidcPassportModule } from './oidc-passport.module.js'
import type { INestApplication } from '@nestjs/common'
import { Controller, Get, Request, UseGuards } from '@nestjs/common'
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
import type * as Express from 'express'
import { agent } from 'supertest'
import { DirectGrant } from '@oidc-adapters/core'
import { OidcAuthGuard } from './oidc-passport.guard.js'
import { AuthGuard } from '@nestjs/passport'

interface TestResponse {
  public: boolean,
  user: typeof Express.request.user
}

describe('OidcPassportModule (default)', () => {
  @Controller()
  class TestController {
    @Get('/public')
    getPublic (@Request() request: Express.Request) {
      return {
        public: true,
        user: request.user
      }
    }

    @Get('/private')
    @UseGuards(OidcAuthGuard)
    getPrivate (@Request() request: Express.Request) {
      return {
        public: false,
        user: request.user
      }
    }
  }

  let app: INestApplication

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [OidcPassportModule.forRoot({ options: { allowedIssuers: ['http://localhost:8109/realms/master'] } })],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  describe('OidcPassportStrategy', () => {
    it('should access public endpoint without authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeUndefined()
    })

    it('should not access private endpoint without authentication', async () => {
      return agent(app.getHttpServer())
        .get('/private')
        .expect(401)
    })

    it('should access private endpoint with valid bearer token and return user', async () => {
      const directGrant = new DirectGrant({
        authority: 'http://localhost:8109/realms/master',
        client_id: 'admin-cli'
      })

      const tokenReponseJson = await directGrant.password('admin', 'admin')

      const response = await agent(app.getHttpServer())
        .get('/private')
        .set('Authorization', `Bearer ${tokenReponseJson.access_token}`)
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeFalsy()
      expect(testBody.user?.jwtPayload).toBeDefined()
    })
  })
})

describe('OidcPassportModule (custom name)', () => {
  @Controller()
  class TestController {
    @Get('/public')
    getPublic (@Request() request: Express.Request) {
      return {
        public: true,
        user: request.user
      }
    }

    @Get('/private')
    @UseGuards(AuthGuard('oidc-custom'))
    getPrivate (@Request() request: Express.Request) {
      return {
        public: false,
        user: request.user
      }
    }
  }

  let app: INestApplication

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [OidcPassportModule.forRoot({
        options: { allowedIssuers: ['http://localhost:8109/realms/master'] },
        strategyName: 'oidc-custom'
      })],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  describe('OidcPassportStrategy', () => {
    it('should access public endpoint without authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeUndefined()
    })

    it('should not access private endpoint without authentication', async () => {
      return agent(app.getHttpServer())
        .get('/private')
        .expect(401)
    })

    it('should access private endpoint with valid bearer token and return user', async () => {
      const directGrant = new DirectGrant({
        authority: 'http://localhost:8109/realms/master',
        client_id: 'admin-cli'
      })

      const tokenReponseJson = await directGrant.password('admin', 'admin')

      const response = await agent(app.getHttpServer())
        .get('/private')
        .set('Authorization', `Bearer ${tokenReponseJson.access_token}`)
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeFalsy()
      expect(testBody.user?.jwtPayload).toBeDefined()
    })
  })
})
