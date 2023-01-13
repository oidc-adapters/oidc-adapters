import { Test } from '@nestjs/testing'
import type { INestApplication } from '@nestjs/common'
import { Controller, Delete, Get, Request, UseGuards } from '@nestjs/common'
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
import type * as Express from 'express'
import { agent } from 'supertest'
import { PermissionBasedAccessControlModule } from './permission-based-access-control.module.js'
import { OidcAuthGuard, OidcPassportModule } from '../oidc-passport/index.js'
import { PermissionsGuard } from './permissions.guard.js'
import { directGrant } from '../../__tests__/utils/auth.js'
import { KeycloakPermissionsProvider } from '@oidc-adapters/keycloak'

interface TestResponse {
  user: typeof Express.request.user
}

describe('PermissionBasedAccessControlModule', () => {
  let app: INestApplication

  @Controller()
  class TestController {
    @Get('/public')
    getPublic (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }

    @Get('/resource1')
    @UseGuards(OidcAuthGuard(), PermissionsGuard('resource1#read'))
    readResource1 (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }

    @Delete('/resource1')
    @UseGuards(OidcAuthGuard(), PermissionsGuard('resource1#delete'))
    deleteResource1 (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }

    @Get('/admin-resource')
    @UseGuards(OidcAuthGuard(), PermissionsGuard('admin-resource'))
    readAdminResource (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }
  }

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [
        OidcPassportModule.forRoot({ options: { allowedIssuers: ['http://localhost:8109/realms/keycloak-test'] } }),
        PermissionBasedAccessControlModule.forRoot({
          providerType: 'user',
          provider: (user) => new KeycloakPermissionsProvider({ token: user.jwtPayload, encodedToken: user.jwt })
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

  it('should access public endpoint without authentication', async () => {
    const response = await agent(app.getHttpServer())
      .get('/public')
      .expect(200)

    const testBody = response.body as TestResponse

    expect(testBody.user).toBeUndefined()
  })

  it('should not access resource1 GET without authentication', async () => {
    await agent(app.getHttpServer())
      .get('/resource1')
      .expect(401)
  })

  it('should access resource1 GET with authentication', async () => {
    await agent(app.getHttpServer())
      .get('/resource1')
      .use(await directGrant('admin', 'admin'))
      .expect(200)
  })

  it('should access resource1 DELETE endpoint with authentication and permission', async () => {
    await agent(app.getHttpServer())
      .delete('/resource1')
      .use(await directGrant('admin', 'admin'))
      .expect(200)
  })

  it('should not access resource1 DELETE endpoint with authentication but no permission', async () => {
    await agent(app.getHttpServer())
      .delete('/resource1')
      .use(await directGrant('user', 'user'))
      .expect(403)
  })

  it('should access admin-resource GET endpoint with authentication and permission', async () => {
    await agent(app.getHttpServer())
      .get('/admin-resource')
      .use(await directGrant('admin', 'admin'))
      .expect(200)
  })

  it('should not access admin-resource GET endpoint with authentication but no permission', async () => {
    await agent(app.getHttpServer())
      .get('/admin-resource')
      .use(await directGrant('user', 'user'))
      .expect(403)
  })
})
