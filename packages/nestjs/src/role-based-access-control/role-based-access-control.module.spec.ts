import { Test } from '@nestjs/testing'
import type { INestApplication } from '@nestjs/common'
import { Controller, Get, Request, UseGuards } from '@nestjs/common'
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
import type * as Express from 'express'
import { agent } from 'supertest'
import { RoleBasedAccessControlModule } from './role-based-access-control.module.js'
import type { KeycloakTokenClaims } from '@oidc-adapters/keycloak'
import { KeycloakRolesProvider } from '@oidc-adapters/keycloak'
import { OidcAuthGuard, OidcPassportModule } from '../oidc-passport/index.js'
import { RolesGuard } from './roles.guard.js'
import { directGrant } from '../../__tests__/utils/auth.js'

interface TestResponse {
  public: boolean,
  user: typeof Express.request.user
}

@Controller()
class TestController {
  @Get('/public')
  getPublic (@Request() request: Express.Request) {
    return {
      public: true,
      user: request.user
    }
  }

  @Get('/admin')
  @UseGuards(OidcAuthGuard(), RolesGuard('admin'))
  getAdmin (@Request() request: Express.Request) {
    return {
      public: true,
      user: request.user
    }
  }

  @Get('/realm-admin')
  @UseGuards(OidcAuthGuard(), RolesGuard('realm:realm-admin'))
  getRealmAdmin (@Request() request: Express.Request) {
    return {
      public: true,
      user: request.user
    }
  }
}

describe('RoleBasedAccessControlModule (default)', () => {
  let app: INestApplication

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [
        OidcPassportModule.forRoot({ options: { allowedIssuers: ['http://localhost:8109/realms/nestjs-test'] } }),
        RoleBasedAccessControlModule.forRoot({
          providerType: 'user',
          provider: (user) => new KeycloakRolesProvider(user.jwtPayload as KeycloakTokenClaims)
        })
      ],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  describe('RoleBasedAccessControlModule', () => {
    it('should access public endpoint without authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeUndefined()
    })

    it('should not access admin endpoint without authentication', async () => {
      await agent(app.getHttpServer())
        .get('/admin')
        .expect(401)
    })

    it('should access admin endpoint with authentication', async () => {
      await agent(app.getHttpServer())
        .get('/admin')
        .use(await directGrant('admin', 'admin'))
        .expect(200)
    })

    it('should not access admin endpoint with authentication but invalid role', async () => {
      await agent(app.getHttpServer())
        .get('/admin')
        .use(await directGrant('user', 'user'))
        .expect(403)
    })

    it('should access realm admin endpoint with authentication', async () => {
      await agent(app.getHttpServer())
        .get('/realm-admin')
        .use(await directGrant('admin', 'admin'))
        .expect(200)
    })

    it('should not access realm admin endpoint with authentication but missing role', async () => {
      await agent(app.getHttpServer())
        .get('/realm-admin')
        .use(await directGrant('user', 'user'))
        .expect(403)
    })
  })
})
